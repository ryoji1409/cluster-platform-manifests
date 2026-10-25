# sbom-collector（Kubernetes SBOM収集・可視化 PoC）

クラスタ上で稼働中のコンテナイメージを収集し、Syft で CycloneDX SBOM を生成します。
回収した SBOM をローカルの `generate_report.py` でオフライン HTML レポートに変換し、
パッケージ → イメージ → Namespace / Pod の対応を検索できるようにします。

目的は、新しい CVE が公開されたときに影響を受けうるイメージとワークロードを素早く特定することです。
現時点では CVE との自動照合は未実装です。

## ファイル構成

| ファイル | 内容 |
| --- | --- |
| `01-rbac.yaml` | Namespace `security`、ServiceAccount / ClusterRole / ClusterRoleBinding `sbom-collector`（`pods` の `list` のみ） |
| `02-scripts.yaml` | ConfigMap `sbom-collector-scripts`（`collect.sh` / `scan.sh`） |
| `03-job.yaml` | Job `sbom-collector-<ランダム>`（`generateName`、collector → syft → result-holder） |
| `generate_report.py` | ローカルで HTML レポートを生成するスクリプト（Python 3.9 以上、標準ライブラリのみ） |

## 処理の流れ

1. **collector**（initContainer, `alpine:3.22`）: 全 Namespace の Pod を取得し、Container Status の `imageID` から Digest 付き参照を抽出して `workloads.tsv` / `images.tsv` / `unresolved.tsv` を出力
2. **syft**（initContainer, `anchore/syft:v1.54.1-debug`）: `images.tsv` の各イメージを `syft scan --from registry` で順次スキャン（最大 `MAX_IMAGES`=100 件、1 件あたり `SCAN_TIMEOUT`=600 秒）し、`sbom/<image-name>-<digest先頭12文字>.json`・`scan-results.tsv`・`scan-summary.tsv` を出力。失敗したイメージは `errors/` にエラーログを残し、処理を続行
3. **result-holder**（container, `alpine:3.22`）: `kubectl cp` で回収できるよう 30 分間待機

データは emptyDir（`sizeLimit: 5Gi`）の `/data` に保存されるため、Pod 削除時に消えます。
Job は完了から 1 時間後（`ttlSecondsAfterFinished: 3600`）に削除されます。

### 終了条件

Kubernetes の Job の成否と、イメージごとのスキャンの成否は分けて扱います。
個別イメージの失敗（Pull 不可、認証エラー、タイムアウトなど）では syft は正常終了し、result-holder が起動するため、成功分の SBOM と失敗内容を回収できます。

| 状況 | syft の終了コード | 動作 |
| --- | --- | --- |
| 全件成功 | `0` | result-holder 起動 |
| 一部失敗・全件失敗 | `0` | result-holder 起動、失敗を `scan-results.tsv` / `errors/` に記録 |
| スキャン対象 0 件 | `0` | result-holder 起動、WARNING を出力（collector のログと `unresolved.tsv` を確認） |
| collector が失敗 | 非 0 | Job 失敗 |
| `images.tsv` がない | 非 0 | Job 失敗 |

result-holder が 30 分待機するため、Job が Complete になるのは回収時間の経過後です。
スキャンの成否は Job の状態ではなく、`scan-summary.tsv` と `scan-results.tsv` で確認してください。

## 実行手順

```bash
# 1. RBAC とスクリプトを適用（初回、または変更時のみ）
kubectl apply -f 01-rbac.yaml -f 02-scripts.yaml

# 2. Job を作成（generateName のため apply ではなく create）
JOB=$(kubectl create -f 03-job.yaml -o name)   # 例: job.batch/sbom-collector-x7k2p
echo "$JOB"

# 3. ログ確認
kubectl logs -n security "$JOB" -c collector -f
kubectl logs -n security "$JOB" -c syft -f

# 4. 結果を回収（result-holder 起動後 30 分以内）
POD=$(kubectl -n security get pods -l "batch.kubernetes.io/job-name=${JOB#*/}" \
  -o jsonpath='{.items[0].metadata.name}')
kubectl -n security cp -c result-holder "$POD:/data" ./sbom-results
cat ./sbom-results/scan-summary.tsv          # 成功・失敗・未スキャン件数を確認

# 5. レポート生成
cd sbom-results
python3 ../generate_report.py
# => sbom-report_YYYYMMDD_HHMMSS_ffffff_Asia-Tokyo.html（出力パスを標準出力に表示）

# または、ディレクトリを指定して実行
# python3 generate_report.py --input-dir ./sbom-results --output-dir ./reports

# 6. 生成された HTML をブラウザで開く
```

Job は `generateName: sbom-collector-` で作成されるため、再実行時も既存の Job を削除せずに手順 2 から実行できます。
`kubectl apply` は `generateName` を扱えないため、Job の作成には必ず `kubectl create` を使用してください。
過去の Job は `ttlSecondsAfterFinished` により自動削除されます。実行中・保持中の Job は次で確認できます。

```bash
kubectl -n security get jobs -l app=sbom-collector
```

`logs` は Pod が起動する前に実行するとエラーになるため、その場合は少し待ってから再実行してください。

## 出力ファイル（/data）

| ファイル | 内容 |
| --- | --- |
| `images.tsv` | スキャン可能な一意のイメージ参照（`SCAN_REF`） |
| `workloads.tsv` | `NAMESPACE` / `POD` / `NODE` / `TYPE` / `CONTAINER` / `IMAGE` / `IMAGE_ID` / `SCAN_REF` |
| `unresolved.tsv` | Digest 付き参照を取得できなかったコンテナ |
| `images-list.txt` | Syft 用のヘッダーなし入力リスト |
| `scan-results.tsv` | `IMAGE` / `FILE` / `STATUS`（`SUCCESS` / `FAILED`）。`FILE` は成功時は SBOM、失敗時はエラーログのパス |
| `scan-summary.tsv` | `METRIC` / `VALUE`（`total` / `attempted` / `success` / `failed` / `skipped`）。`skipped` は `MAX_IMAGES` 超過で未スキャンの件数 |
| `sbom/*.json` | CycloneDX JSON SBOM |
| `errors/*.log` | 失敗したイメージの Syft の標準エラー出力。タイムアウト時は syft コンテナのログに `FAILED (exit 143)` と出力される |

`errors/*.log` には内部 Registry の URL などが含まれる可能性があるため、共有する前に内容を確認してください。

## HTML レポート

### オプション

| オプション | 既定値 | 内容 |
| --- | --- | --- |
| `[directory]` / `--input-dir` | カレントディレクトリ | `kubectl cp` で回収したディレクトリ（`--input-dir` が優先） |
| `--output-dir` | `.` | 出力先ディレクトリ（なければ作成） |
| `--prefix` | `sbom-report` | 出力ファイル名の接頭辞（英数字・`.`・`_`・`-` のみ） |

出力ファイル名は `<prefix>_<YYYYMMDD_HHMMSS_マイクロ秒>_Asia-Tokyo.html` で、既存ファイルは上書きしません。
入力 TSV の必須列が欠けている場合などはエラー終了（終了コード 1）します。

### 入力の扱い

- SBOM は CycloneDX JSON（`bomFormat: CycloneDX`）と Trivy JSON（`Results`）に対応
- CycloneDX の入れ子コンポーネントも展開。`container` / `file` / `operating-system` 型はパッケージとして扱わない
- `scan-results.tsv` の `FILE`（Pod 内パス `/data/sbom/...`）は、入力ディレクトリの `sbom/` 配下のファイル名で解決
- `workloads.tsv` は `SCAN_REF`（Digest 付き参照）でイメージと関連付け。`SCAN_REF` が空の行は `IMAGE` で照合するため、スキャン結果とは一致せず `NOT_SCANNED` になる
- 以下は「入力警告」としてレポート内に一覧表示
  - SBOM を読み込めない、または形式が未対応
  - `scan-results.tsv` に存在しないワークロード参照（Digest 未解決、`MAX_IMAGES` 超過など）
  - `scan-results.tsv` に登録されていない `sbom/*.json`

### レポートの機能

- 表示単位の切り替え: Image 単位 / Package 単位 / Workload 単位（Workload = Namespace / Pod / Container / 種別 / Image の組み合わせ）
- 検索条件（すべて AND、部分一致は大文字・小文字を区別しない）
  - 部分一致: Image 名、Pod 名、Container 名、Package 名、Version、Type、License、PURL
  - 完全一致（プルダウン）: Namespace、Pod（選択した Namespace に絞り込み）、Scan status
- Namespace・Pod・Container の条件は同じ Workload 行で判定し、Package 系の条件は同じ Package で判定する
- 各行の「関連情報」「稼働先」から、関連する Package・Workload の詳細を表示
- ページネーション 25 / 50 / 100 行、表示中のページの行だけを生成
- 生成日時（Asia/Tokyo）をページ上部に表示
- 外部通信・CDN・DB・Web サーバー不要（データは HTML 内に JSON として埋め込み、CSP で外部通信を禁止）
- HTML には SBOM とワークロードの情報が含まれるため、取り扱いに注意すること

## 既知の制約

- collector が失敗した場合や `images.tsv` がない場合は initContainer が異常終了し、result-holder が起動しないため `kubectl cp` で回収できない
- スキャン失敗の理由は `errors/*.log` に残るが、HTML レポートには表示されない（`FAILED` の状態のみ表示）
- 重複排除はレジストリ参照文字列の完全一致で、別リポジトリ名から同一 Digest を参照するケースは統合されない
- 収集対象は実行時点で存在する Pod のみ
- Registry 認証、DNS 未登録の Harbor、自己署名 CA は `03-job.yaml` では未設定（対応手順は「プライベート Harbor への対応」を参照）
- マルチアーキテクチャの厳密な識別は未対応
- 永続保存、スキャン済みキャッシュ、CVE 照合（Grype）、通知は未実装

## プライベート Harbor への対応

現在の `03-job.yaml` に `hostAliases`・Registry 認証用 Secret・CA 証明書用 ConfigMap の 3 つを追加すれば対応できます。
既存の Collector や `scan.sh` は基本的に変更不要です。

### 1. Harbor 認証用 Secret と CA 証明書

Harbor の Robot Account など、対象プロジェクトの Pull 権限を持つアカウントで Secret を作成します。

```bash
kubectl -n security create secret docker-registry harbor-auth \
  --docker-server=harbor.example.local \
  --docker-username='robot$sbom-reader' \
  --docker-password='<ROBOT_TOKEN>'
```

`harbor.example.local` は実際の Harbor FQDN に置き換えてください。パスワードをコマンド履歴に残さない運用が望ましいです。

Harbor の証明書が社内 CA で署名されている場合は、その CA 証明書も登録します。

```bash
kubectl -n security create configmap harbor-ca \
  --from-file=ca.crt=./harbor-ca.crt
```

公開 CA の証明書を使用しており、Syft から既に信頼できる場合は CA の追加は不要です。
その場合は、下記の `SYFT_REGISTRY_CA_CERT`、`harbor-ca` の volumeMount と volume も削除してください（存在しない ConfigMap を参照すると Pod が起動しません）。

### 2. 03-job.yaml の変更箇所

既存の Job の `spec.template.spec` に追記します。

```yaml
spec:
  template:
    spec:
      serviceAccountName: sbom-collector
      restartPolicy: Never

      # Harbor の LoadBalancer IP と FQDN の対応
      hostAliases:
        - ip: "10.0.0.100"
          hostnames:
            - "harbor.example.local"

      initContainers:
        # collector は既存のまま

        - name: syft
          image: anchore/syft:v1.54.1-debug
          command:
            - /busybox/sh
            - /scripts/scan.sh

          env:
            - name: MAX_IMAGES
              value: "100"

            - name: SCAN_TIMEOUT
              value: "600"

            # Docker 形式の認証情報
            - name: DOCKER_CONFIG
              value: /registry-auth

            # Harbor の CA 証明書
            - name: SYFT_REGISTRY_CA_CERT
              value: /certs/ca.crt

          volumeMounts:
            - name: scripts
              mountPath: /scripts
              readOnly: true

            - name: data
              mountPath: /data

            - name: registry-auth
              mountPath: /registry-auth
              readOnly: true

            - name: harbor-ca
              mountPath: /certs
              readOnly: true

      volumes:
        # 既存の scripts と data はそのまま

        - name: registry-auth
          secret:
            secretName: harbor-auth
            items:
              - key: .dockerconfigjson
                path: config.json

        - name: harbor-ca
          configMap:
            name: harbor-ca
```

`hostAliases` は Pod 単位なので、collector・syft・result-holder の全コンテナに適用されます。
一方、Registry 認証情報と CA 証明書は、実際にイメージをスキャンする syft コンテナだけにマウントします。

### 3. 補足

Syft は `DOCKER_CONFIG` で指定したディレクトリの `config.json` から認証情報を読み込みます。
また、`SYFT_REGISTRY_CA_CERT` で独自 CA 証明書を指定できます。

設定後にエラーが出た場合は、syft のログまたは回収した `errors/<image-name>-<digest>.log` のメッセージから切り分けできます。

| エラー | 主な確認箇所 |
| --- | --- |
| `no such host` | `hostAliases` の FQDN |
| `connection refused` / `timeout` | Pod から Harbor LB IP への疎通 |
| `x509: certificate signed by unknown authority` | CA 証明書 |
| `401 Unauthorized` | Robot Account・Secret |
| `403 Forbidden` | Harbor プロジェクトの Pull 権限 |

**注意点:** Job のイメージ取得に使う `imagePullSecrets` と、Syft が Registry から解析対象のイメージを取得するための `DOCKER_CONFIG` は別物です。

この設定であれば、既存の `scan.sh` の次の処理をそのまま使えます。

```sh
/syft scan "$image" \
  --from registry \
  -o "cyclonedx-json=$output"
```

`hostAliases` の FQDN は、`images.tsv` に記録される Harbor のホスト名と一致させてください。
`hostAliases` は Kubernetes 公式が Pod の `/etc/hosts` を変更する方法として案内しているものです。

まず Harbor のイメージ 1 件をスキャンできるか確認し、正常なら全イメージに広げるのが確実です。
