"""Bounded, offline Burp XML analysis. No network activity or auditor imports."""
from __future__ import annotations
import base64
import hashlib
import io
import re
from urllib.parse import urlsplit, parse_qsl
from defusedxml import ElementTree as ET

MAX_ITEMS = 20000
MAX_MESSAGE = 2 * 1024 * 1024
MAX_FINDINGS = 10000

class PassiveError(ValueError):
    pass

def _message(item, name):
    node = item.find(name)
    if node is None or not node.text:
        return b''
    raw = node.text.strip()
    try:
        if node.get('base64', 'false').lower() == 'true':
            if len(raw) > MAX_MESSAGE * 2:
                raise PassiveError('Oversized encoded message')
            data = base64.b64decode(raw, validate=True)
        else:
            data = raw.encode('utf-8')
    except (ValueError, UnicodeError) as exc:
        raise PassiveError(f'Invalid {name} encoding') from exc
    if len(data) > MAX_MESSAGE:
        raise PassiveError('Oversized message')
    return data

def _headers(data):
    head = data.split(b'\r\n\r\n', 1)[0].split(b'\n\n', 1)[0]
    result = {}
    for line in head.splitlines()[1:]:
        if b':' in line:
            k, v = line.split(b':', 1)
            result.setdefault(k.decode('latin1').strip().lower(), []).append(v.decode('latin1').strip())
    return result

def _body(data):
    if b'\r\n\r\n' in data:
        return data.split(b'\r\n\r\n', 1)[1]
    if b'\n\n' in data:
        return data.split(b'\n\n', 1)[1]
    return b''

def _allowed(url, scope):
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            return False
        host = parsed.hostname.rstrip('.').lower()
        # Do not permit wildcard, regex, parent-domain, or other scope kinds here.
        for rule in scope.get('out_of_scope', []):
            value = str(rule.get('value', '')).lower().lstrip('*.')
            if rule.get('kind') == 'host' and host == value:
                return False
            if rule.get('kind') in ('wildcard', 'domain') and (host == value or host.endswith('.' + value)):
                return False
        return any(rule.get('kind') == 'host' and host == str(rule.get('value', '')).rstrip('.').lower() for rule in scope.get('in_scope', []))
    except (ValueError, AttributeError):
        return False

def analyze_burp(path, scope, selected):
    """Return observations only; never claim exploitation or invoke active auditors."""
    selected = set(selected)
    stats = {'items_seen': 0, 'in_scope': 0, 'out_of_scope': 0, 'unreadable': 0}
    findings = []
    if not isinstance(scope.get('in_scope'), list) or not isinstance(scope.get('out_of_scope', []), list):
        raise PassiveError('Invalid scope lists')
    try:
        context = ET.iterparse(str(path), events=('end',))
        for _, item in context:
            if item.tag != 'item':
                continue
            stats['items_seen'] += 1
            if stats['items_seen'] > MAX_ITEMS:
                raise PassiveError(f'Capture exceeds {MAX_ITEMS} items')
            url = (item.findtext('url') or '').strip()
            if not _allowed(url, scope):
                stats['out_of_scope'] += 1
                item.clear()
                continue
            stats['in_scope'] += 1
            try:
                request = _message(item, 'request')
                response = _message(item, 'response')
            except PassiveError:
                stats['unreadable'] += 1
                item.clear()
                continue
            req_headers = _headers(request)
            resp_headers = _headers(response)
            body = _body(response)
            status = (response.splitlines() or [b''])[0].decode('latin1', 'replace')[:120]
            url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
            # Never persist request/response contents, query strings, or secrets.
            def add(auditor, code, confidence, detail):
                if len(findings) < MAX_FINDINGS:
                    findings.append({'auditor': auditor, 'code': code, 'confidence': confidence,
                                     'verification': 'not_verified', 'url_sha256_prefix': url_hash,
                                     'host': urlsplit(url).hostname, 'http_status_line': status,
                                     'detail': detail})
            if 'sensitive_data_exposure' in selected:
                if re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', body):
                    add('sensitive_data_exposure', 'private_key_material_in_response', 'high', 'Private-key PEM marker observed in response body; review locally')
                if re.search(rb'(?i)(?:aws_access_key_id|AKIA[0-9A-Z]{16})', body):
                    add('sensitive_data_exposure', 'potential_aws_key_reference', 'low', 'AWS credential pattern observed; not validated')
            if 'cors' in selected:
                origin = req_headers.get('origin', [None])[0]
                acao = resp_headers.get('access-control-allow-origin', [None])[0]
                creds = resp_headers.get('access-control-allow-credentials', [''])[0].lower()
                if origin and acao == origin and creds == 'true':
                    add('cors', 'origin_reflected_with_credentials', 'low', 'Origin reflected with credentials enabled; exploitability unverified')
            if 'xss' in selected and body:
                # Only pre-existing test markers; ordinary reflected text is not XSS proof.
                for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=False)[:100]:
                    if re.fullmatch(r'(?:muninn|xss)[-_]?[a-z0-9]{8,64}', value, flags=re.I) and value.encode() in body:
                        add('xss', 'test_marker_reflected', 'low', 'Distinctive test marker reflected; execution not demonstrated')
                        break
            item.clear()
    except ET.ParseError as exc:
        raise PassiveError(f'Invalid Burp XML: {exc}') from exc
    return {'stats': stats, 'findings': findings, 'finding_limit_reached': len(findings) >= MAX_FINDINGS}
