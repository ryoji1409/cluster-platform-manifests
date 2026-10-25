#!/usr/bin/env python3
"""Offline CycloneDX/Trivy SBOM report. Python 3.9+, standard library only.

Usage: python3 generate_report.py --input-dir ./sbom-results --output-dir .
See README.md for TSV columns and matching rules.
"""
import argparse
import csv
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

JST = timezone(timedelta(hours=9), 'Asia/Tokyo')

def read_tsv(path, required):
    with path.open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f, delimiter='\t')
        if not reader.fieldnames:
            raise ValueError(f'{path}: header is missing')
        keys = [re.sub(r'[^A-Z0-9]', '', k.upper()) for k in reader.fieldnames]
        if len(set(keys)) != len(keys):
            raise ValueError(f'{path}: duplicate column names')
        rows = []
        for n, row in enumerate(reader, 2):
            if None in row:
                raise ValueError(f'{path}:{n}: too many columns')
            item = {k: (row.get(old) or '').strip() for k, old in zip(keys, reader.fieldnames)}
            if any(item.values()):
                rows.append(item)
        for alternatives in required:
            if not any(k in keys for k in alternatives):
                raise ValueError(f'{path}: required column: {" / ".join(alternatives)}')
        return rows

def get(row, *names):
    return next((row[k] for k in names if row.get(k)), '')

def image_ref(value):
    return re.sub(r'^(?:docker-pullable|docker|containerd|cri-o)://', '', value.strip())

def licenses(component):
    result = []
    for item in component.get('licenses') or []:
        lic = item.get('license') or {}
        value = item.get('expression') or lic.get('id') or lic.get('name')
        if value:
            result.append(str(value))
    return ', '.join(sorted(set(result)))

def packages(doc):
    found = []
    def walk(components):
        for c in components or []:
            # CycloneDX containers/files are not software packages.
            if c.get('type') not in ('container', 'file', 'operating-system'):
                name = str(c.get('name') or '')
                group = str(c.get('group') or '')
                if group:
                    name = group.rstrip('/') + '/' + name
                if name:
                    found.append(dict(name=name, version=str(c.get('version') or ''),
                                      type=str(c.get('type') or ''), purl=str(c.get('purl') or ''),
                                      license=licenses(c)))
            walk(c.get('components'))
    if doc.get('bomFormat') == 'CycloneDX':
        walk(doc.get('components'))
    elif isinstance(doc.get('Results'), list):
        for result in doc['Results']:
            for p in result.get('Packages') or []:
                lic = p.get('Licenses') or []
                found.append(dict(name=str(p.get('Name') or ''), version=str(p.get('Version') or ''),
                                  type=str(result.get('Type') or ''),
                                  purl=str((p.get('Identifier') or {}).get('PURL') or ''),
                                  license=', '.join(lic) if isinstance(lic, list) else str(lic)))
    else:
        raise ValueError('unsupported SBOM (expected CycloneDX or Trivy JSON with Results)')
    return sorted({tuple(p.values()): p for p in found}.values(), key=lambda p: (p['name'], p['version'], p['purl']))

def build_data(root):
    scans = read_tsv(root / 'scan-results.tsv', [('IMAGE', 'SCANREF'), ('FILE', 'SBOMFILE'), ('STATUS',)])
    work = read_tsv(root / 'workloads.tsv', [('NAMESPACE', 'NS'), ('POD', 'PODNAME'),
                                           ('SCANREF', 'IMAGE', 'IMAGEID')])
    warnings, images, by_ref = [], [], {}
    for row in scans:
        ref = image_ref(get(row, 'IMAGE', 'SCANREF'))
        if not ref:
            raise ValueError('scan-results.tsv: empty IMAGE/SCAN_REF')
        if ref in by_ref:
            raise ValueError(f'duplicate scan image: {ref}')
        filename = get(row, 'FILE', 'SBOMFILE')
        original = Path(filename)
        # kubectl cp changes /data/sbom/... to <input-dir>/sbom/...
        candidates = [root / 'sbom' / original.name]
        if not original.is_absolute():
            candidates.insert(0, root / original)
        source = next((p for p in candidates if p.is_file()), None)
        item = dict(ref=ref, status=get(row, 'STATUS'), file=filename, packages=[], error='')
        if item['status'].upper() in ('SUCCESS', 'OK', 'SUCCEEDED'):
            try:
                if source is None:
                    raise ValueError(f'SBOM file missing: {filename}')
                item['packages'] = packages(json.loads(source.read_text(encoding='utf-8-sig')))
            except (ValueError, OSError, TypeError, AttributeError) as e:
                item['error'] = str(e)
                warnings.append(f'{ref}: {e}')
        else:
            item['error'] = 'スキャン未成功: ' + item['status']
        by_ref[ref] = len(images)
        images.append(item)
    workloads, seen = [], set()
    for row in work:
        # Prefer digest-based SCAN_REF; never guess using a digest alone or an image tag.
        ref = image_ref(get(row, 'SCANREF', 'IMAGE', 'IMAGEID'))
        namespace, pod = get(row, 'NAMESPACE', 'NS'), get(row, 'POD', 'PODNAME')
        if not namespace or not pod:
            raise ValueError('workloads.tsv: empty Namespace or Pod')
        if ref not in by_ref:
            by_ref[ref] = len(images)
            images.append(dict(ref=ref, status='NOT_SCANNED', file='', packages=[], error='scan-results.tsv に一致する参照なし'))
            warnings.append(f'未対応のWorkload参照: {ref or "(empty)"}')
        w = dict(namespace=namespace, pod=pod, container=get(row, 'CONTAINER', 'CONTAINERNAME'),
                 kind=get(row, 'CONTAINERTYPE', 'TYPE', 'KIND'), image=by_ref[ref])
        key = tuple(w.values())
        if key not in seen:
            seen.add(key)
            workloads.append(w)
    used = {Path(i['file']).name for i in images if i['file']}
    for path in sorted((root / 'sbom').glob('*.json')):
        if path.name not in used:
            warnings.append(f'scan-results.tsv に登録されていないSBOM: {path.name}')
    return dict(images=images, workloads=workloads, warnings=warnings)

HTML = r'''<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>SBOM Explorer</title><style>
:root{font-family:system-ui,sans-serif;color:#1d3045;background:#f3f6fa}body{margin:0}header{background:#142d49;color:white;padding:28px 4%}h1{margin:0 0 8px;font-size:28px}header p{margin:4px 0;color:#d4e4f4}main{padding:24px 4%}.panel{background:white;border:1px solid #d9e2ec;border-radius:12px;padding:20px;margin-bottom:18px}.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}label{display:flex;flex-direction:column;gap:5px;font-size:13px;font-weight:600}input,select,button{font:inherit;padding:9px;border:1px solid #b8c8d8;border-radius:6px;background:white;color:#16324e}button{cursor:pointer}button:disabled{opacity:.4;cursor:default}button.active{background:#176b85;color:white;border-color:#176b85}.toolbar,.pager{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.toolbar{margin-bottom:16px}.pager{justify-content:space-between;margin-top:16px}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #e2e9f0;vertical-align:top;overflow-wrap:anywhere;min-width:90px}th{background:#f0f5f9}td small{display:block;color:#586c80;margin-top:5px}.muted{color:#586c80;font-size:13px}.badge{background:#edf4f8;padding:3px 7px;border-radius:4px}.warning{color:#975515}summary{cursor:pointer}#detail{max-height:65vh;overflow:auto}details{margin-top:10px}h2{font-size:18px}.counts{font-size:15px;line-height:1.7}a{color:#176b85}button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #00a6c2}footer{padding:0 4% 24px;font-size:12px;color:#586c80}
</style></head><body><header><h1>SBOM Explorer</h1><p>オフラインで確認する、イメージ・パッケージ・稼働先の一覧</p><p id="generated"></p></header><main>
<div class="panel counts" id="stats"></div>
<div class="panel"><div class="toolbar" role="group" aria-label="表示単位"><button data-view="image" class="active" aria-pressed="true">Image単位</button><button data-view="package" aria-pressed="false">Package単位</button><button data-view="workload" aria-pressed="false">Workload単位</button></div>
<div class="filters">
<label>Image名<input id="imageQ" type="search" placeholder="部分一致"></label>
<label>Namespace（完全一致）<select id="namespace"><option value="">すべて</option></select></label>
<label>Pod（完全一致）<select id="pod"><option value="">すべて</option></select></label>
<label>Pod名<input id="podQ" type="search" placeholder="部分一致"></label>
<label>Container名<input id="containerQ" type="search" placeholder="部分一致"></label>
<label>Package名<input id="packageQ" type="search" placeholder="部分一致"></label>
<label>Version<input id="versionQ" type="search" placeholder="部分一致"></label>
<label>Type<input id="typeQ" type="search" placeholder="部分一致"></label>
<label>License<input id="licenseQ" type="search" placeholder="部分一致"></label>
<label>PURL<input id="purlQ" type="search" placeholder="部分一致"></label>
<label>Scan status<select id="status"><option value="">すべて</option></select></label>
<label>1ページの件数<select id="size"><option>25</option><option>50</option><option>100</option></select></label>
</div><p class="muted">検索は大文字・小文字を区別しない部分一致、項目間はAND条件です。Namespace・Pod・Container条件は同じWorkload行、Package条件は同じPackageで判定します。Workload＝Namespace / Pod / Container / 種別 / Image の組み合わせ。</p><button id="reset">条件をリセット</button></div>
<div class="panel"><div id="result" role="status" aria-live="polite"></div><div class="tablewrap"><table><thead id="head"></thead><tbody id="body"></tbody></table></div><div class="pager"><button id="prev">← 前へ</button><span id="page"></span><button id="next">次へ →</button></div></div>
<div class="panel" id="detailPanel" hidden><div class="toolbar"><h2 id="detailTitle"></h2><button id="closeDetail">閉じる</button></div><div id="detail"></div><div class="pager"><button id="detailPrev">← 前へ</button><span id="detailPage"></span><button id="detailNext">次へ →</button></div></div>
<div class="panel" id="warnings" hidden><details><summary id="warningTitle"></summary><ul id="warningList"></ul></details></div>
</main><footer>外部通信・CDN・DB不要。このHTMLには抽出したSBOM情報とWorkload情報が含まれます。</footer>
<script id="data" type="application/json">__DATA__</script><script>
'use strict';
const DATA=JSON.parse(document.getElementById('data').textContent);
const $=id=>document.getElementById(id), lower=x=>String(x??'').toLowerCase();
const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let view='image', page=1, filtered=[], detailRows=[], detailPage=1;
const searchIds=['imageQ','podQ','containerQ','packageQ','versionQ','typeQ','licenseQ','purlQ'];
const fieldIds={name:'packageQ',version:'versionQ',type:'typeQ',license:'licenseQ',purl:'purlQ'};
const imageWorks=DATA.images.map(()=>[]);
DATA.workloads.forEach(w=>{imageWorks[w.image].push(w);w.search=[w.pod,w.container].map(lower)});
// Shared package records and memberships avoid expanding every package into every Pod.
const packageMap=new Map(), packageRows=[];
DATA.images.forEach((im,i)=>{
 im.search=lower(im.ref);
 im.packages.forEach(p=>{
  const key=JSON.stringify([p.name,p.version,p.type,p.license,p.purl]);
  let rec=packageMap.get(key);
  if(!rec){rec={...p,images:[],search:Object.fromEntries(Object.keys(fieldIds).map(k=>[k,lower(p[k])]))};packageMap.set(key,rec);packageRows.push(rec)}
  rec.images.push(i);
 });
 // Replace per-image package objects with the shared records.
 im.packages=im.packages.map(p=>packageMap.get(JSON.stringify([p.name,p.version,p.type,p.license,p.purl])));
});
const addOptions=(el,values)=>{el.replaceChildren(new Option('すべて',''));[...new Set(values)].sort().forEach(v=>{if(v)el.add(new Option(v,v))})};
addOptions($('namespace'),DATA.workloads.map(w=>w.namespace));
addOptions($('status'),DATA.images.map(im=>im.status));
function updatePods(){const old=$('pod').value;addOptions($('pod'),DATA.workloads.filter(w=>!$('namespace').value||w.namespace===$('namespace').value).map(w=>w.pod));if([...$('pod').options].some(o=>o.value===old))$('pod').value=old}
updatePods();
$('generated').textContent='生成日時: '+DATA.generated+' (Asia/Tokyo, UTC+09:00)';
$('stats').textContent=`${DATA.images.length.toLocaleString()} Images　 /　${packageRows.length.toLocaleString()} Packages（名前・版・Type・License・PURLの組み合わせ）　 /　${DATA.workloads.length.toLocaleString()} Workloads`;
if(DATA.warnings.length){$('warnings').hidden=false;$('warningTitle').textContent=`入力警告 ${DATA.warnings.length}件`;$('warningList').replaceChildren(...DATA.warnings.map(w=>{const li=document.createElement('li');li.textContent=w;return li}))}
function criteria(){return {q:Object.fromEntries(searchIds.map(id=>[id,lower($(id).value.trim())])), ns:$('namespace').value,pod:$('pod').value,status:$('status').value}}
function workMatches(w,c){return (!c.ns||w.namespace===c.ns)&&(!c.pod||w.pod===c.pod)&&w.search[0].includes(c.q.podQ)&&w.search[1].includes(c.q.containerQ)}
function hasWork(c){return !!(c.ns||c.pod||c.q.podQ||c.q.containerQ)}
function pkgMatches(p,c){return Object.entries(fieldIds).every(([k,id])=>p.search[k].includes(c.q[id]))}
function hasPkg(c){return Object.values(fieldIds).some(id=>c.q[id])}
let eligibleImages=new Set(), matchingWorks=[];
function apply(){
 const c=criteria();matchingWorks=imageWorks.map(ws=>ws.filter(w=>workMatches(w,c)));
 eligibleImages=new Set();
 DATA.images.forEach((im,i)=>{if(im.search.includes(c.q.imageQ)&&(!c.status||im.status===c.status)&&(!hasWork(c)||matchingWorks[i].length)&&(!hasPkg(c)||im.packages.some(p=>pkgMatches(p,c))))eligibleImages.add(i)});
 if(view==='image')filtered=[...eligibleImages];
 else if(view==='package')filtered=packageRows.filter(p=>pkgMatches(p,c)&&p.images.some(i=>eligibleImages.has(i)));
 else filtered=DATA.workloads.filter(w=>eligibleImages.has(w.image)&&workMatches(w,c));
 page=1;closeDetail();render();
}
function workLabel(w){return `${w.namespace} / ${w.pod} / ${w.container||'—'}${w.kind?' ('+w.kind+')':''}`}
function td(x){return '<td>'+esc(x)+'</td>'}
function button(label,index){return `<button data-detail="${index}">${esc(label)}</button>`}
function render(){
 const size=+$('size').value,totalPages=Math.max(1,Math.ceil(filtered.length/size));page=Math.min(page,totalPages);
 const rows=filtered.slice((page-1)*size,page*size), c=criteria();
 const headers=view==='image'?['Image / Scan status','Packages','Workloads','詳細']:view==='package'?['Package / Version','Type / License','PURL','Images','詳細']:['Namespace / Pod','Container / 種別','Image','Packages','詳細'];
 $('head').innerHTML='<tr>'+headers.map(h=>'<th scope="col">'+esc(h)+'</th>').join('')+'</tr>';
 $('body').innerHTML=rows.map((r,index)=>{
  const absolute=(page-1)*size+index;
  if(view==='image'){const im=DATA.images[r];return '<tr><td>'+esc(im.ref)+'<small>'+esc(im.status)+(im.error?' · '+esc(im.error):'')+'</small></td>'+td(im.packages.filter(p=>pkgMatches(p,c)).length)+td(matchingWorks[r].length)+'<td>'+button('関連情報',absolute)+'</td></tr>'}
  if(view==='package')return '<tr><td>'+esc(r.name)+'<small>'+esc(r.version)+'</small></td><td>'+esc(r.type)+'<small>'+esc(r.license||'—')+'</small></td>'+td(r.purl)+td(r.images.filter(i=>eligibleImages.has(i)).length)+'<td>'+button('稼働先',absolute)+'</td></tr>';
  return '<tr><td>'+esc(r.namespace)+'<small>'+esc(r.pod)+'</small></td><td>'+esc(r.container||'—')+'<small>'+esc(r.kind)+'</small></td>'+td(DATA.images[r.image].ref)+td(DATA.images[r.image].packages.filter(p=>pkgMatches(p,c)).length)+'<td>'+button('関連情報',absolute)+'</td></tr>';
 }).join('')||'<tr><td colspan="5">該当するデータがありません。</td></tr>';
 $('result').textContent=`${filtered.length.toLocaleString()}件 · ${view==='image'?'Image':view==='package'?'Package':'Workload'}単位`;
 $('page').textContent=`${page} / ${totalPages} ページ`;$('prev').disabled=page===1;$('next').disabled=page===totalPages;
}
function closeDetail(){$('detailPanel').hidden=true;detailRows=[]}
function showDetail(index){
 const row=filtered[index],c=criteria();detailRows=[];detailPage=1;
 const related=(i)=>{matchingWorks[i].forEach(w=>detailRows.push(['Workload',workLabel(w),DATA.images[i].ref]));if(!matchingWorks[i].length)detailRows.push(['Image',DATA.images[i].ref,hasWork(c)?'該当Workloadなし':'Workload登録なし'])};
 if(view==='package'){$('detailTitle').textContent=row.name+' '+row.version;row.images.filter(i=>eligibleImages.has(i)).forEach(related)}
 else{const i=view==='image'?row:row.image;$('detailTitle').textContent=DATA.images[i].ref;
 DATA.images[i].packages.filter(p=>pkgMatches(p,c)).forEach(p=>detailRows.push(['Package',p.name+' '+p.version,[p.type,p.license,p.purl].filter(Boolean).join(' · ')]));
 if(view==='workload')detailRows.push(['Workload',workLabel(row),'']);else related(i)}
 $('detailPanel').hidden=false;renderDetail();$('detailPanel').scrollIntoView({block:'start',behavior:'smooth'});
}
function renderDetail(){const size=+$('size').value,pages=Math.max(1,Math.ceil(detailRows.length/size));detailPage=Math.min(detailPage,pages);$('detail').innerHTML='<table><thead><tr><th>種別</th><th>名前</th><th>情報</th></tr></thead><tbody>'+detailRows.slice((detailPage-1)*size,detailPage*size).map(r=>'<tr>'+r.map(td).join('')+'</tr>').join('')+'</tbody></table>';$('detailPage').textContent=`${detailRows.length}件 · ${detailPage} / ${pages} ページ`;$('detailPrev').disabled=detailPage===1;$('detailNext').disabled=detailPage===pages}
let timer;
function queueApply(){clearTimeout(timer);timer=setTimeout(apply,180)}
searchIds.forEach(id=>$(id).addEventListener('input',queueApply));
['namespace','pod','status'].forEach(id=>$(id).addEventListener('change',()=>{clearTimeout(timer);if(id==='namespace')updatePods();apply()}));
$('size').addEventListener('change',()=>{page=1;render();if(!$('detailPanel').hidden)renderDetail()});
document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>{clearTimeout(timer);view=b.dataset.view;document.querySelectorAll('[data-view]').forEach(x=>{x.classList.toggle('active',x===b);x.setAttribute('aria-pressed',String(x===b))});apply()}));
$('reset').onclick=()=>{clearTimeout(timer);searchIds.forEach(id=>$(id).value='');['namespace','pod','status'].forEach(id=>$(id).value='');updatePods();apply()};
$('prev').onclick=()=>{page--;closeDetail();render()};$('next').onclick=()=>{page++;closeDetail();render()};
$('body').onclick=e=>{const b=e.target.closest('[data-detail]');if(b)showDetail(+b.dataset.detail)};
$('closeDetail').onclick=closeDetail;$('detailPrev').onclick=()=>{detailPage--;renderDetail()};$('detailNext').onclick=()=>{detailPage++;renderDetail()};
apply();
</script></body></html>'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', nargs='?', type=Path, help='input directory (default: current directory)')
    parser.add_argument('--input-dir', type=Path)
    parser.add_argument('--output-dir', type=Path, default=Path('.'))
    parser.add_argument('--prefix', default='sbom-report', help='output filename prefix')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', args.prefix):
        parser.error('--prefix accepts only letters, digits, dot, underscore and hyphen')
    try:
        data = build_data(args.input_dir or args.directory or Path('.'))
        now = datetime.now(JST)
        data['generated'] = now.isoformat(timespec='seconds')
        payload = json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
        args.output_dir.mkdir(parents=True, exist_ok=True)
        output = args.output_dir / f'{args.prefix}_{now:%Y%m%d_%H%M%S_%f}_Asia-Tokyo.html'
        # Exclusive creation protects existing reports from accidental overwrite.
        with output.open('x', encoding='utf-8') as f:
            f.write(HTML.replace('__DATA__', payload))
        print(output.resolve())
        print(f'{len(data["images"])} images, {len(data["workloads"])} workloads, {len(data["warnings"])} warnings', file=sys.stderr)
        return 0
    except (OSError, ValueError, csv.Error) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
