#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnsmap_async_tuned_full.py

- Fully async DNS lookups via dnspython's dns.asyncresolver
- Spreads queries across many public resolvers (DEFAULT_NAMESERVERS)
- Wildcard detection filters false positives
- Auto-tunes concurrency and timeout every 5s (P90 latency + timeout rate + queue pressure)
- Hard per-query deadline, per-resolver health/cooldown, bulletproof workers

Usage:
  python3 dnsmap_async_tuned_full.py example.com

Requires:
  pip install dnspython
"""
import asyncio
import random
import sys
import time
from collections import deque, defaultdict
from time import monotonic
from typing import Set, List, Dict

import dns.asyncresolver as aresolver
import dns.exception
import dns.resolver as dresolver  # exceptions here

# --------- Resolver pool ---------
DEFAULT_NAMESERVERS = [
    "1.1.1.1", "1.0.0.1",
    "1.1.1.3", "1.0.0.3",
    "4.2.2.1", "4.2.2.2",
    "4.2.2.3", "4.2.2.4",
    "8.8.8.8", "8.8.4.4",
    "8.26.56.26", "8.20.247.20",
    "9.9.9.9", "9.9.9.10",
    "23.253.163.53",
    "45.90.28.0", "45.90.30.0",
    "64.6.64.6", "64.6.65.6",
    "77.88.8.8",
    "89.233.43.71",
    "94.140.14.14", "94.140.15.15",
    "156.154.70.1", "156.154.71.1",
    "185.228.168.9", "185.228.169.9",
    "198.101.242.72",
    "208.76.50.50",
    "208.67.222.222", "208.67.220.220",
    "216.146.35.35", "216.146.36.36",
]
random.shuffle(DEFAULT_NAMESERVERS)

# ---------- Auto-tuning limits ----------
CONC_MIN = 64
CONC_MAX = 256
TARGET_P90_MS = 400.0
TIMEOUT_MIN = 1.0
TIMEOUT_MAX = 5.0
ADJUST_PERIOD = 5.0
METRICS_WINDOW = 1000
RAMP_MIN_SAMPLES = 200
# ---------------------------------------

# ---------- Initial seeds ----------
INITIAL_CONCURRENCY = 100
INITIAL_TIMEOUT = 2.0
# -----------------------------------

# ---------- Full subdomain set (wrapped to ≤80 chars/line) ----------
subs_set = {
    'a', 'aa', 'ab', 'ac', 'access', 'accounting', 'accounts', 'ad', 'admin',
    'administrator', 'ae', 'af', 'ag', 'ah', 'ai', 'aix', 'aj', 'ak', 'al', 'am',
    'an', 'ao', 'ap', 'api', 'apollo', 'app', 'aq', 'ar', 'archivos', 'as', 'at',
    'au', 'aula', 'aulas', 'av', 'aw', 'ax', 'ay', 'ayuda', 'az', 'b', 'ba',
    'backup', 'backups', 'bart', 'bb', 'bc', 'bd', 'be', 'beta', 'bf', 'bg',
    'bh', 'bi', 'biblioteca', 'billing', 'bj', 'bk', 'bl', 'blackboard', 'blog',
    'blogs', 'bm', 'bn', 'bo', 'bp', 'bq', 'br', 'bs', 'bsd', 'bt', 'bu', 'bv',
    'bw', 'bx', 'by', 'bz', 'c', 'ca', 'carro', 'cart', 'cas', 'catalog',
    'catalogo', 'catalogue', 'cb', 'cc', 'cd', 'ce', 'cf', 'cg', 'ch', 'chat',
    'chimera', 'chronos', 'ci', 'cicd', 'citrix', 'cj', 'ck', 'cl', 'classroom',
    'clientes', 'clients', 'cloud', 'cm', 'cn', 'co', 'connect', 'controller',
    'correoweb', 'cp', 'cpanel', 'cq', 'cr', 'cs', 'csg', 'ct', 'cu',
    'customers', 'cv', 'cw', 'cx', 'cy', 'cz', 'd', 'da', 'data', 'db', 'dbs',
    'dc', 'dd', 'de', 'demo', 'demon', 'demostration', 'descargas', 'dev',
    'develop', 'developers', 'development', 'df', 'dg', 'dh', 'di', 'diana',
    'directory', 'dj', 'dk', 'dl', 'dm', 'dmz', 'dn', 'do', 'docker', 'docs',
    'domain', 'domaincontroller', 'domain-controller', 'download', 'downloads',
    'dp', 'dq', 'dr', 'ds', 'dt', 'du', 'dv', 'dw', 'dx', 'dy', 'dz', 'e', 'ea',
    'eaccess', 'eb', 'ec', 'ed', 'ee', 'ef', 'eg', 'eh', 'ei', 'ej', 'ejemplo',
    'ejemplos', 'ek', 'el', 'em', 'email', 'en', 'enrutador', 'eo', 'ep', 'eq',
    'er', 'es', 'et', 'eu', 'ev', 'eventos', 'events', 'ew', 'ex', 'example',
    'examples', 'exchange', 'extranet', 'ey', 'ez', 'f', 'fa', 'fb', 'fc', 'fd',
    'fe', 'feed', 'ff', 'fg', 'fh', 'fi', 'files', 'finance', 'firewall',
    'firmware', 'fj', 'fk', 'fl', 'fm', 'fn', 'fo', 'foro', 'foros', 'forum',
    'forums', 'fp', 'fq', 'fr', 'freebsd', 'fs', 'ft', 'ftp', 'ftpd', 'fu', 'fv',
    'fw', 'fx', 'fy', 'fz', 'g', 'ga', 'galeria', 'gallery', 'gateway', 'gb',
    'gc', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi', 'gilford', 'gj', 'gk', 'gl', 'gm',
    'gn', 'go', 'gp', 'gq', 'gr', 'groups', 'groupwise', 'gs', 'gt', 'gu',
    'guest', 'guia', 'guide', 'gv', 'gw', 'gx', 'gy', 'gz', 'h', 'ha', 'hb',
    'hc', 'hd', 'he', 'help', 'helpdesk', 'hera', 'heracles', 'hercules', 'hf',
    'hg', 'hh', 'hi', 'hj', 'hk', 'hl', 'hm', 'hn', 'ho', 'home', 'homer',
    'hotspot', 'hp', 'hq', 'hr', 'hs', 'ht', 'hu', 'hv', 'hw', 'hx', 'hy',
    'hypernova', 'hz', 'i', 'ia', 'ib', 'ic', 'id', 'ie', 'if', 'ig', 'ih', 'ii',
    'ij', 'ik', 'il', 'im', 'images', 'imail', 'imap', 'imap3', 'imap3d',
    'imapd', 'imaps', 'imgs', 'imogen', 'in', 'inmuebles', 'internal', 'interno',
    'intranet', 'io', 'ip', 'ip6', 'ipsec', 'ipv6', 'iq', 'ir', 'irc', 'ircd',
    'is', 'isa', 'it', 'iu', 'iv', 'iw', 'ix', 'iy', 'iz', 'j', 'ja', 'jabber',
    'jb', 'jc', 'jd', 'je', 'jenkins', 'jf', 'jg', 'jh', 'ji', 'jj', 'jk', 'jl',
    'jm', 'jn', 'jo', 'jp', 'jq', 'jr', 'js', 'jt', 'ju', 'jupiter', 'jv', 'jw',
    'jx', 'jy', 'jz', 'k', 'k8s', 'ka', 'kb', 'kc', 'kd', 'ke', 'kf', 'kg', 'kh',
    'ki', 'kj', 'kk', 'kl', 'km', 'kn', 'ko', 'kp', 'kq', 'kr', 'ks', 'kt', 'ku',
    'kv', 'kw', 'kx', 'ky', 'kz', 'l', 'la', 'lab', 'laboratories',
    'laboratorio', 'laboratory', 'labs', 'lb', 'lc', 'ld', 'le', 'lf', 'lg',
    'lh', 'li', 'library', 'linux', 'lisa', 'lj', 'lk', 'll', 'lm', 'ln', 'lo',
    'localhost', 'log', 'login', 'logon', 'logs', 'lp', 'lq', 'lr', 'ls', 'lt',
    'lu', 'lv', 'lw', 'lx', 'ly', 'lz', 'm', 'ma', 'mail', 'mailgate', 'manager',
    'manual', 'marketing', 'mb', 'mc', 'md', 'me', 'media', 'member', 'members',
    'mercury', 'meta', 'meta01', 'meta02', 'meta03', 'meta1', 'meta2', 'meta3',
    'mf', 'mg', 'mh', 'mi', 'miembros', 'minerva', 'mj', 'mk', 'ml', 'mm', 'mn',
    'mo', 'mob', 'mobile', 'moodle', 'movil', 'mp', 'mq', 'mr', 'ms', 'mssql',
    'mt', 'mu', 'mv', 'mw', 'mx', 'mx0', 'mx01', 'mx02', 'mx03', 'mx1', 'mx2',
    'mx3', 'my', 'mysql', 'mz', 'n', 'na', 'nb', 'nc', 'nd', 'ne', 'nelson',
    'neon', 'net', 'netmail', 'news', 'nf', 'ng', 'nh', 'ni', 'nj', 'nk', 'nl',
    'nm', 'nn', 'no', 'novell', 'np', 'nq', 'nr', 'ns', 'ns0', 'ns01', 'ns02',
    'ns03', 'ns1', 'ns2', 'ns3', 'nt', 'ntp', 'nu', 'nv', 'nw', 'nx', 'ny', 'nz',
    'o', 'oa', 'oauth', 'ob', 'oc', 'od', 'oe', 'of', 'og', 'oh', 'oi', 'oj',
    'ok', 'okta', 'ol', 'om', 'on', 'online', 'oo', 'op', 'oq', 'or', 'ora',
    'oracle', 'os', 'osx', 'ot', 'ou', 'ov', 'ow', 'owa', 'ox', 'oy', 'oz', 'p',
    'pa', 'partners', 'pb', 'pc', 'pcanywhere', 'pd', 'pe', 'pegasus',
    'pendrell', 'personal', 'pf', 'pg', 'ph', 'photo', 'photos', 'pi', 'pj',
    'pk', 'pl', 'platform', 'pm', 'pn', 'po', 'pop', 'pop3', 'portal',
    'postgresql', 'postman', 'postmaster', 'pp', 'ppp', 'pq', 'pr', 'preprod',
    'pre-prod', 'private', 'prod', 'proxy', 'prueba', 'pruebas', 'ps', 'pt',
    'pu', 'pub', 'public', 'pv', 'pw', 'px', 'py', 'pz', 'q', 'qa', 'qb', 'qc',
    'qd', 'qe', 'qf', 'qg', 'qh', 'qi', 'qj', 'qk', 'ql', 'qm', 'qn', 'qo', 'qp',
    'qq', 'qr', 'qs', 'qt', 'qu', 'qv', 'qw', 'qx', 'qy', 'qz', 'r', 'ra', 'ras',
    'rb', 'rc', 'rd', 're', 'remote', 'reports', 'research', 'resources',
    'restricted', 'rf', 'rg', 'rh', 'ri', 'rj', 'rk', 'rl', 'rm', 'rn', 'ro',
    'robinhood', 'router', 'rp', 'rq', 'rr', 'rs', 'rt', 'rtr', 'ru', 'rv', 'rw',
    'rx', 'ry', 'rz', 's', 'sa', 'sales', 'sample', 'samples', 'sandbox', 'sb',
    'sc', 'sd', 'se', 'search', 'secure', 'seguro', 'server', 'services',
    'servicios', 'servidor', 'sf', 'sg', 'sh', 'sharepoint', 'shop', 'shopping',
    'si', 'sj', 'sk', 'sl', 'sm', 'sms', 'smtp', 'sn', 'so', 'social', 'socios',
    'solaris', 'soporte', 'sp', 'sq', 'sql', 'squirrel', 'squirrelmail', 'sr',
    'ss', 'ssh', 'sso', 'st', 'staff', 'staging', 'stats', 'status', 'store',
    'su', 'sun', 'support', 'sv', 'sw', 'sx', 'sy', 'sz', 't', 'ta', 'tb', 'tc',
    'td', 'te', 'test', 'tf', 'tftp', 'tg', 'th', 'ti', 'tienda', 'tj', 'tk',
    'tl', 'tm', 'tn', 'to', 'tp', 'tq', 'tr', 'ts', 'tt', 'tu', 'tunnel', 'tv',
    'tw', 'tx', 'ty', 'tz', 'u', 'ua', 'uat', 'ub', 'uc', 'ud', 'ue', 'uf', 'ug',
    'uh', 'ui', 'uj', 'uk', 'ul', 'um', 'un', 'unix', 'uo', 'up', 'updates',
    'upload', 'uploads', 'uq', 'ur', 'us', 'ut', 'uu', 'uv', 'uw', 'ux', 'uy',
    'uz', 'v', 'va', 'vb', 'vc', 'vd', 've', 'ventas', 'vf', 'vg', 'vh', 'vi',
    'virtual', 'vista', 'vj', 'vk', 'vl', 'vm', 'vn', 'vnc', 'vo', 'vp', 'vpn',
    'vpn1', 'vpn2', 'vpn3', 'vq', 'vr', 'vs', 'vt', 'vu', 'vv', 'vw', 'vx', 'vy',
    'vz', 'w', 'wa', 'wap', 'wb', 'wc', 'wd', 'we', 'web', 'web0', 'web01',
    'web02', 'web03', 'web1', 'web2', 'web3', 'webadmin', 'webct', 'weblog',
    'webmail', 'webmaster', 'webmin', 'wf', 'wg', 'wh', 'wi', 'win', 'windows',
    'wj', 'wk', 'wl', 'wm', 'wn', 'wo', 'wp', 'wq', 'wr', 'ws', 'wt', 'wu', 'wv',
    'ww', 'ww0', 'ww01', 'ww02', 'ww03', 'ww1', 'ww2', 'ww3', 'wx', 'wy', 'wz',
    'x', 'xa', 'xanthus', 'xb', 'xc', 'xd', 'xe', 'xf', 'xg', 'xh', 'xi', 'xj',
    'xk', 'xl', 'xm', 'xn', 'xo', 'xp', 'xq', 'xr', 'xs', 'xt', 'xu', 'xv', 'xw',
    'xx', 'xy', 'xz', 'y', 'ya', 'yb', 'yc', 'yd', 'ye', 'yf', 'yg', 'yh', 'yi',
    'yj', 'yk', 'yl', 'ym', 'yn', 'yo', 'yp', 'yq', 'yr', 'ys', 'yt', 'yu', 'yv',
    'yw', 'yx', 'yy', 'yz', 'z', 'za', 'zb', 'zc', 'zd', 'ze', 'zeus', 'zf',
    'zg', 'zh', 'zi', 'zj', 'zk', 'zl', 'zm', 'zn', 'zo', 'zp', 'zq', 'zr', 'zs',
    'zt', 'zu', 'zv', 'zw', 'zx', 'zy', 'zz', 'a-01', 'a-02', 'a-1', 'a-2',
    'a-api', 'a-app', 'a-beta', 'a-dev', 'a-internal', 'a-prod', 'a-srv',
    'a-stage', 'a-staging', 'a-svc', 'a-test', 'a-web', 'a1', 'a2', 'a3', 'a4',
    'a5', 'aa-01', 'aa-02', 'aa-1', 'aa-2', 'aa-api', 'aa-app', 'aa-beta',
    'aa-dev', 'aa-internal', 'aa-prod', 'aa-srv', 'aa-stage', 'aa-staging',
    'aa-svc', 'aa-test', 'aa-web', 'aa1', 'aa2', 'aa3', 'aa4', 'aa5', 'ab-01',
    'ab-02', 'ab-1', 'ab-2', 'ab-api', 'ab-app', 'ab-beta', 'ab-dev',
    'ab-internal', 'ab-prod', 'ab-srv', 'ab-stage', 'ab-staging', 'ab-svc',
    'ab-test', 'ab-web', 'ab1', 'ab2', 'ab3', 'ab4', 'ab5', 'ac-01', 'ac-02',
    'ac-1', 'ac-2', 'ac-api', 'ac-app', 'ac-beta', 'ac-dev', 'ac-internal',
    'ac-prod', 'ac-srv', 'ac-stage', 'ac-staging', 'ac-svc', 'ac-test', 'ac-web',
    'ac1', 'ac2', 'ac3', 'ac4', 'ac5', 'access-01', 'access-02', 'access-1',
    'access-2', 'access-api', 'access-app', 'access-beta', 'access-dev',
    'access-internal', 'access-prod', 'access-srv', 'access-stage',
    'access-staging', 'access-svc', 'access-test', 'access-web', 'access1',
    'access2', 'access3', 'access4', 'access5', 'account', 'account-01',
    'account-02', 'account-1', 'account-2', 'account-api', 'account-app',
    'account-beta', 'account-dev', 'account-internal', 'account-prod',
    'account-srv', 'account-stage', 'account-staging', 'account-svc',
    'account-test', 'account-web', 'account1', 'account2', 'account3',
    'account4', 'account5', 'accounting-01', 'accounting-02', 'accounting-1',
    'accounting-2', 'accounting-api', 'accounting-app', 'accounting-beta',
    'accounting-dev', 'accounting-internal', 'accounting-prod', 'accounting-srv',
    'accounting-stage', 'accounting-staging', 'accounting-svc',
    'accounting-test', 'accounting-web', 'accounting1', 'accounting2',
    'accounting3', 'accounting4', 'accounting5', 'accounts-01', 'accounts-02',
    'accounts-1', 'accounts-2', 'accounts-api', 'accounts-app', 'accounts-beta',
    'accounts-dev', 'accounts-internal', 'accounts-prod', 'accounts-srv',
    'accounts-stage', 'accounts-staging', 'accounts-svc', 'accounts-test',
    'accounts-web', 'accounts1', 'accounts2', 'accounts3', 'accounts4',
    'accounts5', 'ad-01', 'ad-02', 'ad-1', 'ad-2', 'ad-api', 'ad-app', 'ad-beta',
    'ad-dev', 'ad-internal', 'ad-prod', 'ad-srv', 'ad-stage', 'ad-staging',
    'ad-svc', 'ad-test', 'ad-web', 'ad1', 'ad2', 'ad3', 'ad4', 'ad5', 'admin-01',
    'admin-02', 'admin-1', 'admin-2', 'admin-api', 'admin-app', 'admin-assets',
    'admin-auth', 'admin-beta', 'admin-billing', 'admin-cdn', 'admin-control',
    'admin-dashboard', 'admin-dev', 'admin-developer', 'admin-docs',
    'admin-files', 'admin-help', 'admin-internal', 'admin-login',
    'admin-manager', 'admin-media', 'admin-panel', 'admin-panel-01',
    'admin-panel-02', 'admin-panel-1', 'admin-panel-2', 'admin-panel-api',
    'admin-panel-app', 'admin-panel-beta', 'admin-panel-dev',
    'admin-panel-internal', 'admin-panel-prod', 'admin-panel-srv',
    'admin-panel-stage', 'admin-panel-staging', 'admin-panel-svc',
    'admin-panel-test', 'admin-panel-web', 'admin-panel1', 'admin-panel2',
    'admin-panel3', 'admin-panel4', 'admin-panel5', 'admin-payments',
    'admin-portal', 'admin-prod', 'admin-production', 'admin-secure',
    'admin-shop', 'admin-srv', 'admin-stage', 'admin-staging', 'admin-static',
    'admin-status', 'admin-store', 'admin-support', 'admin-svc', 'admin-test',
    'admin-uploads', 'admin-web', 'admin.api', 'admin.assets', 'admin.auth',
    'admin.beta', 'admin.billing', 'admin.cdn', 'admin.control',
    'admin.dashboard', 'admin.dev', 'admin.developer', 'admin.docs',
    'admin.files', 'admin.help', 'admin.login', 'admin.manager', 'admin.media',
    'admin.payments', 'admin.portal', 'admin.prod', 'admin.production',
    'admin.secure', 'admin.shop', 'admin.staging', 'admin.static',
    'admin.status', 'admin.store', 'admin.support', 'admin.test',
    'admin.uploads', 'admin1', 'admin2', 'admin2-01', 'admin2-02', 'admin2-1',
    'admin2-2', 'admin2-api', 'admin2-app', 'admin2-beta', 'admin2-dev',
    'admin2-internal', 'admin2-prod', 'admin2-srv', 'admin2-stage',
    'admin2-staging', 'admin2-svc', 'admin2-test', 'admin2-web', 'admin21',
    'admin22', 'admin23', 'admin24', 'admin25', 'admin3', 'admin4', 'admin5',
    'adminapi', 'adminassets', 'adminauth', 'adminbeta', 'adminbilling',
    'admincdn', 'admincontrol', 'admindashboard', 'admindev', 'admindeveloper',
    'admindocs', 'adminfiles', 'adminhelp', 'administrator-01',
    'administrator-02', 'administrator-1', 'administrator-2',
    'administrator-api', 'administrator-app', 'administrator-beta',
    'administrator-dev', 'administrator-internal', 'administrator-prod',
    'administrator-srv', 'administrator-stage', 'administrator-staging',
    'administrator-svc', 'administrator-test', 'administrator-web',
    'administrator1', 'administrator2', 'administrator3', 'administrator4',
    'administrator5', 'adminlogin', 'adminmanager', 'adminmedia',
    'adminpayments', 'adminportal', 'adminprod', 'adminproduction',
    'adminsecure', 'adminshop', 'adminstaging', 'adminstatic', 'adminstatus',
    'adminstore', 'adminsupport', 'admintest', 'adminuploads', 'ae-01', 'ae-02',
    'ae-1', 'ae-2', 'ae-api', 'ae-app', 'ae-beta', 'ae-dev', 'ae-internal',
    'ae-prod', 'ae-srv', 'ae-stage', 'ae-staging', 'ae-svc', 'ae-test', 'ae-web',
    'ae1', 'ae2', 'ae3', 'ae4', 'ae5', 'af-01', 'af-02', 'af-1', 'af-2',
    'af-api', 'af-app', 'af-beta', 'af-dev', 'af-internal', 'af-prod', 'af-srv',
    'af-stage', 'af-staging', 'af-svc', 'af-test', 'af-web', 'af1', 'af2', 'af3',
    'af4', 'af5', 'ag-01', 'ag-02', 'ag-1', 'ag-2', 'ag-api', 'ag-app',
    'ag-beta', 'ag-dev', 'ag-internal', 'ag-prod', 'ag-srv', 'ag-stage',
    'ag-staging', 'ag-svc', 'ag-test', 'ag-web', 'ag1', 'ag2', 'ag3', 'ag4',
    'ag5', 'ah-01', 'ah-02', 'ah-1', 'ah-2', 'ah-api', 'ah-app', 'ah-beta',
    'ah-dev', 'ah-internal', 'ah-prod', 'ah-srv', 'ah-stage', 'ah-staging',
    'ah-svc', 'ah-test', 'ah-web', 'ah1', 'ah2', 'ah3', 'ah4', 'ah5', 'ai-01',
    'ai-02', 'ai-1', 'ai-2', 'ai-api', 'ai-app', 'ai-beta', 'ai-dev',
    'ai-internal', 'ai-prod', 'ai-srv', 'ai-stage', 'ai-staging', 'ai-svc',
    'ai-test', 'ai-web', 'ai1', 'ai2', 'ai3', 'ai4', 'ai5', 'aix-01', 'aix-02',
    'aix-1', 'aix-2', 'aix-api', 'aix-app', 'aix-beta', 'aix-dev',
    'aix-internal', 'aix-prod', 'aix-srv', 'aix-stage', 'aix-staging', 'aix-svc',
    'aix-test', 'aix-web', 'aix1', 'aix2', 'aix3', 'aix4', 'aix5', 'aj-01',
    'aj-02', 'aj-1', 'aj-2', 'aj-api', 'aj-app', 'aj-beta', 'aj-dev',
    'aj-internal', 'aj-prod', 'aj-srv', 'aj-stage', 'aj-staging', 'aj-svc',
    'aj-test', 'aj-web', 'aj1', 'aj2', 'aj3', 'aj4', 'aj5', 'ak-01', 'ak-02',
    'ak-1', 'ak-2', 'ak-api', 'ak-app', 'ak-beta', 'ak-dev', 'ak-internal',
    'ak-prod', 'ak-srv', 'ak-stage', 'ak-staging', 'ak-svc', 'ak-test', 'ak-web',
    'ak1', 'ak2', 'ak3', 'ak4', 'ak5', 'akamai', 'akamai-01', 'akamai-02',
    'akamai-1', 'akamai-2', 'akamai-api', 'akamai-app', 'akamai-beta',
    'akamai-dev', 'akamai-internal', 'akamai-prod', 'akamai-srv', 'akamai-stage',
    'akamai-staging', 'akamai-svc', 'akamai-test', 'akamai-web', 'akamai1',
    'akamai2', 'akamai3', 'akamai4', 'akamai5', 'al-01', 'al-02', 'al-1', 'al-2',
    'al-api', 'al-app', 'al-beta', 'al-dev', 'al-internal', 'al-prod', 'al-srv',
    'al-stage', 'al-staging', 'al-svc', 'al-test', 'al-web', 'al1', 'al2', 'al3',
    'al4', 'al5', 'alpha', 'alpha-01', 'alpha-02', 'alpha-1', 'alpha-2',
    'alpha-api', 'alpha-app', 'alpha-beta', 'alpha-dev', 'alpha-internal',
    'alpha-prod', 'alpha-srv', 'alpha-stage', 'alpha-staging', 'alpha-svc',
    'alpha-test', 'alpha-web', 'alpha1', 'alpha10', 'alpha11', 'alpha12',
    'alpha13', 'alpha14', 'alpha15', 'alpha16', 'alpha17', 'alpha18', 'alpha19',
    'alpha2', 'alpha20', 'alpha21', 'alpha22', 'alpha23', 'alpha24', 'alpha25',
    'alpha26', 'alpha27', 'alpha28', 'alpha29', 'alpha3', 'alpha30', 'alpha31',
    'alpha32', 'alpha33', 'alpha34', 'alpha35', 'alpha36', 'alpha37', 'alpha38',
    'alpha39', 'alpha4', 'alpha40', 'alpha41', 'alpha42', 'alpha43', 'alpha44',
    'alpha45', 'alpha46', 'alpha47', 'alpha48', 'alpha49', 'alpha5', 'alpha6',
    'alpha7', 'alpha8', 'alpha9', 'am-01', 'am-02', 'am-1', 'am-2', 'am-api',
    'am-app', 'am-beta', 'am-dev', 'am-internal', 'am-prod', 'am-srv',
    'am-stage', 'am-staging', 'am-svc', 'am-test', 'am-web', 'am1', 'am2', 'am3',
    'am4', 'am5', 'amazonaws', 'amazonaws-01', 'amazonaws-02', 'amazonaws-1',
    'amazonaws-2', 'amazonaws-api', 'amazonaws-app', 'amazonaws-beta',
    'amazonaws-dev', 'amazonaws-internal', 'amazonaws-prod', 'amazonaws-srv',
    'amazonaws-stage', 'amazonaws-staging', 'amazonaws-svc', 'amazonaws-test',
    'amazonaws-web', 'amazonaws1', 'amazonaws2', 'amazonaws3', 'amazonaws4',
    'amazonaws5', 'an-01', 'an-02', 'an-1', 'an-2', 'an-api', 'an-app',
    'an-beta', 'an-dev', 'an-internal', 'an-prod', 'an-srv', 'an-stage',
    'an-staging', 'an-svc', 'an-test', 'an-web', 'an1', 'an2', 'an3', 'an4',
    'an5', 'analytics', 'analytics-01', 'analytics-02', 'analytics-1',
    'analytics-2', 'analytics-api', 'analytics-app', 'analytics-beta',
    'analytics-dev', 'analytics-internal', 'analytics-prod', 'analytics-srv',
    'analytics-stage', 'analytics-staging', 'analytics-svc', 'analytics-test',
    'analytics-web', 'analytics1', 'analytics1-01', 'analytics1-02',
    'analytics1-1', 'analytics1-2', 'analytics1-api', 'analytics1-app',
    'analytics1-beta', 'analytics1-dev', 'analytics1-internal',
    'analytics1-prod', 'analytics1-srv', 'analytics1-stage',
    'analytics1-staging', 'analytics1-svc', 'analytics1-test', 'analytics1-web',
    'analytics11', 'analytics12', 'analytics13', 'analytics14', 'analytics15',
    'analytics2', 'analytics3', 'analytics4', 'analytics5', 'ao-01', 'ao-02',
    'ao-1', 'ao-2', 'ao-api', 'ao-app', 'ao-beta', 'ao-dev', 'ao-internal',
    'ao-prod', 'ao-srv', 'ao-stage', 'ao-staging', 'ao-svc', 'ao-test', 'ao-web',
    'ao1', 'ao2', 'ao3', 'ao4', 'ao5', 'ap-01', 'ap-02', 'ap-1', 'ap-2',
    'ap-api', 'ap-app', 'ap-beta', 'ap-dev', 'ap-internal', 'ap-northeast-api',
    'ap-northeast-app', 'ap-northeast-cdn', 'ap-northeast-edge',
    'ap-northeast-origin', 'ap-northeast-s3', 'ap-northeast-static',
    'ap-northeast-storage', 'ap-northeast-uploads', 'ap-prod',
    'ap-southeast-api', 'ap-southeast-app', 'ap-southeast-cdn',
    'ap-southeast-edge', 'ap-southeast-origin', 'ap-southeast-s3',
    'ap-southeast-static', 'ap-southeast-storage', 'ap-southeast-uploads',
    'ap-srv', 'ap-stage', 'ap-staging', 'ap-svc', 'ap-test', 'ap-web', 'ap1',
    'ap2', 'ap3', 'ap4', 'ap5', 'api-01', 'api-02', 'api-1', 'api-2',
    'api-admin', 'api-admin-01', 'api-admin-02', 'api-admin-1', 'api-admin-2',
    'api-admin-api', 'api-admin-app', 'api-admin-beta', 'api-admin-dev',
    'api-admin-internal', 'api-admin-prod', 'api-admin-srv', 'api-admin-stage',
    'api-admin-staging', 'api-admin-svc', 'api-admin-test', 'api-admin-web',
    'api-admin1', 'api-admin2', 'api-admin3', 'api-admin4', 'api-admin5',
    'api-ap-northeast', 'api-ap-southeast', 'api-api', 'api-app', 'api-assets',
    'api-auth', 'api-auth-01', 'api-auth-02', 'api-auth-1', 'api-auth-2',
    'api-auth-api', 'api-auth-app', 'api-auth-beta', 'api-auth-dev',
    'api-auth-internal', 'api-auth-prod', 'api-auth-srv', 'api-auth-stage',
    'api-auth-staging', 'api-auth-svc', 'api-auth-test', 'api-auth-web',
    'api-auth1', 'api-auth2', 'api-auth3', 'api-auth4', 'api-auth5', 'api-beta',
    'api-billing', 'api-cdn', 'api-console', 'api-console-01', 'api-console-02',
    'api-console-1', 'api-console-2', 'api-console-api', 'api-console-app',
    'api-console-beta', 'api-console-dev', 'api-console-internal',
    'api-console-prod', 'api-console-srv', 'api-console-stage',
    'api-console-staging', 'api-console-svc', 'api-console-test',
    'api-console-web', 'api-console1', 'api-console2', 'api-console3',
    'api-console4', 'api-console5', 'api-control', 'api-dashboard', 'api-dev',
    'api-developer', 'api-docs', 'api-docs-01', 'api-docs-02', 'api-docs-1',
    'api-docs-2', 'api-docs-api', 'api-docs-app', 'api-docs-beta',
    'api-docs-dev', 'api-docs-internal', 'api-docs-prod', 'api-docs-srv',
    'api-docs-stage', 'api-docs-staging', 'api-docs-svc', 'api-docs-test',
    'api-docs-web', 'api-docs1', 'api-docs2', 'api-docs3', 'api-docs4',
    'api-docs5', 'api-eu-central', 'api-eu-west', 'api-files', 'api-help',
    'api-internal', 'api-login', 'api-manager', 'api-me-central', 'api-media',
    'api-payments', 'api-portal', 'api-prod', 'api-production', 'api-sa-east',
    'api-secure', 'api-shop', 'api-srv', 'api-stage', 'api-staging',
    'api-static', 'api-status', 'api-store', 'api-support', 'api-svc',
    'api-test', 'api-uploads', 'api-us-central', 'api-us-east', 'api-us-west',
    'api-v1', 'api-v1-01', 'api-v1-02', 'api-v1-1', 'api-v1-2', 'api-v1-api',
    'api-v1-app', 'api-v1-beta', 'api-v1-dev', 'api-v1-internal', 'api-v1-prod',
    'api-v1-srv', 'api-v1-stage', 'api-v1-staging', 'api-v1-svc', 'api-v1-test',
    'api-v1-web', 'api-v11', 'api-v12', 'api-v13', 'api-v14', 'api-v15',
    'api-v2', 'api-v2-01', 'api-v2-02', 'api-v2-1', 'api-v2-2', 'api-v2-api',
    'api-v2-app', 'api-v2-beta', 'api-v2-dev', 'api-v2-internal', 'api-v2-prod',
    'api-v2-srv', 'api-v2-stage', 'api-v2-staging', 'api-v2-svc', 'api-v2-test',
    'api-v2-web', 'api-v21', 'api-v22', 'api-v23', 'api-v24', 'api-v25',
    'api-web', 'api.a', 'api.aa', 'api.ab', 'api.ac', 'api.access',
    'api.account', 'api.accounting', 'api.accounts', 'api.ad', 'api.admin',
    'api.admin-panel', 'api.admin2', 'api.administrator', 'api.ae', 'api.af',
    'api.ag', 'api.ah', 'api.ai', 'api.aix', 'api.aj', 'api.ak', 'api.akamai',
    'api.al', 'api.alpha', 'api.am', 'api.amazonaws', 'api.an', 'api.analytics',
    'api.analytics1', 'api.ao', 'api.ap', 'api.api', 'api.api-admin',
    'api.api-auth', 'api.api-console', 'api.api-docs', 'api.api-v1',
    'api.api-v2', 'api.api1', 'api.api2', 'api.apollo', 'api.app', 'api.apps',
    'api.appspot', 'api.appstore', 'api.aq', 'api.ar', 'api.archive',
    'api.archives', 'api.archivos', 'api.as', 'api.assets', 'api.at', 'api.au',
    'api.aula', 'api.aulas', 'api.auth', 'api.auth0', 'api.av', 'api.aw',
    'api.aws', 'api.ax', 'api.ay', 'api.ayuda', 'api.az', 'api.azure', 'api.b',
    'api.ba', 'api.backup', 'api.backup1', 'api.backups', 'api.bart', 'api.bb',
    'api.bc', 'api.bd', 'api.be', 'api.beta', 'api.bf', 'api.bg', 'api.bh',
    'api.bi', 'api.biblioteca', 'api.billing', 'api.billing-api',
    'api.billing-ui', 'api.billing1', 'api.billingportal', 'api.bitbucket',
    'api.bj', 'api.bk', 'api.bl', 'api.blackboard', 'api.blog', 'api.blogs',
    'api.bm', 'api.bn', 'api.bo', 'api.bounce', 'api.bounces', 'api.bp',
    'api.bq', 'api.br', 'api.bs', 'api.bsd', 'api.bt', 'api.bu', 'api.bv',
    'api.bw', 'api.bx', 'api.by', 'api.bz', 'api.c', 'api.ca', 'api.cache',
    'api.call', 'api.calls', 'api.canary', 'api.carro', 'api.cart', 'api.cas',
    'api.catalog', 'api.catalogo', 'api.catalogue', 'api.cb', 'api.cc', 'api.cd',
    'api.cdn', 'api.cdn-01', 'api.cdn-02', 'api.cdn-03', 'api.cdn-asia',
    'api.cdn-edge', 'api.cdn-eu', 'api.cdn-origin', 'api.cdn-uk', 'api.cdn-us',
    'api.cdn1', 'api.cdn2', 'api.cdnworks', 'api.ce', 'api.cf', 'api.cg',
    'api.ch', 'api.chat', 'api.chat1', 'api.checkout', 'api.checkout1',
    'api.checkout2', 'api.chimera', 'api.chronos', 'api.ci', 'api.cicd',
    'api.citrix', 'api.cj', 'api.ck', 'api.cl', 'api.classroom', 'api.clientes',
    'api.clients', 'api.cloud', 'api.cloudflare', 'api.cloudfront', 'api.cm',
    'api.cn', 'api.co', 'api.community', 'api.confluence', 'api.connect',
    'api.console', 'api.console1', 'api.console2', 'api.control',
    'api.control-panel', 'api.controller', 'api.correoweb', 'api.cp',
    'api.cpanel', 'api.cq', 'api.cr', 'api.crm', 'api.cs', 'api.csg', 'api.ct',
    'api.cu', 'api.customer', 'api.customers', 'api.cv', 'api.cw', 'api.cx',
    'api.cy', 'api.cz', 'api.d', 'api.da', 'api.dashboard', 'api.data',
    'api.database', 'api.db', 'api.dbs', 'api.dc', 'api.dd', 'api.de',
    'api.demo', 'api.demo1', 'api.demon', 'api.demostration', 'api.descargas',
    'api.dev', 'api.dev1', 'api.dev2', 'api.develop', 'api.developer',
    'api.developers', 'api.developers-api', 'api.development', 'api.df',
    'api.dg', 'api.dh', 'api.di', 'api.diana', 'api.digitalocean',
    'api.directory', 'api.directory1', 'api.dj', 'api.dk', 'api.dl', 'api.dm',
    'api.dmz', 'api.dn', 'api.dns', 'api.do', 'api.docker', 'api.docs',
    'api.docs-api', 'api.docs-site', 'api.docs1', 'api.docs2',
    'api.documentation', 'api.domain', 'api.domain-controller',
    'api.domaincontroller', 'api.download', 'api.downloads', 'api.dp', 'api.dq',
    'api.dr', 'api.ds', 'api.dt', 'api.du', 'api.dv', 'api.dw', 'api.dx',
    'api.dy', 'api.dz', 'api.e', 'api.ea', 'api.eaccess', 'api.eb', 'api.ec',
    'api.ed', 'api.edge', 'api.edge1', 'api.ee', 'api.ef', 'api.eg', 'api.eh',
    'api.ei', 'api.ej', 'api.ejemplo', 'api.ejemplos', 'api.ek', 'api.el',
    'api.elastic', 'api.em', 'api.email', 'api.en', 'api.enrutador', 'api.eo',
    'api.ep', 'api.eq', 'api.er', 'api.es', 'api.et', 'api.eu', 'api.ev',
    'api.eventos', 'api.events', 'api.events-api', 'api.ew', 'api.ex',
    'api.example', 'api.examples', 'api.exchange', 'api.extranet', 'api.ey',
    'api.ez', 'api.f', 'api.fa', 'api.fastly', 'api.fb', 'api.fc', 'api.fd',
    'api.fe', 'api.feed', 'api.ff', 'api.fg', 'api.fh', 'api.fi', 'api.files',
    'api.fileserver', 'api.fileserver1', 'api.fileserver2', 'api.finance',
    'api.firebase', 'api.firebaseapp', 'api.firewall', 'api.firmware', 'api.fj',
    'api.fk', 'api.fl', 'api.fm', 'api.fn', 'api.fo', 'api.foro', 'api.foros',
    'api.forum', 'api.forums', 'api.fp', 'api.fq', 'api.fr', 'api.freebsd',
    'api.fs', 'api.ft', 'api.ftp', 'api.ftpd', 'api.ftps', 'api.fu', 'api.fv',
    'api.fw', 'api.fx', 'api.fy', 'api.fz', 'api.g', 'api.ga', 'api.galeria',
    'api.gallery', 'api.gateway', 'api.gateway-admin', 'api.gb', 'api.gc',
    'api.gcp', 'api.gd', 'api.ge', 'api.gf', 'api.gg', 'api.gh', 'api.gi',
    'api.gilford', 'api.git', 'api.github', 'api.gitlab', 'api.gj', 'api.gk',
    'api.gl', 'api.gm', 'api.gn', 'api.go', 'api.google',
    'api.googleusercontent', 'api.gp', 'api.gq', 'api.gr', 'api.grafana',
    'api.groups', 'api.groupwise', 'api.gs', 'api.gt', 'api.gu', 'api.guest',
    'api.guia', 'api.guide', 'api.gv', 'api.gw', 'api.gx', 'api.gy', 'api.gz',
    'api.h', 'api.ha', 'api.hb', 'api.hc', 'api.hd', 'api.he', 'api.health',
    'api.healthcheck', 'api.healthz', 'api.heartbeat', 'api.help',
    'api.helpcenter', 'api.helpchat', 'api.helpdesk', 'api.hera', 'api.heracles',
    'api.hercules', 'api.heroku', 'api.hetzner', 'api.hf', 'api.hg', 'api.hh',
    'api.hi', 'api.hj', 'api.hk', 'api.hl', 'api.hm', 'api.hn', 'api.ho',
    'api.home', 'api.home2', 'api.homer', 'api.hooks', 'api.hooks1',
    'api.hotspot', 'api.hp', 'api.hq', 'api.hr', 'api.hs', 'api.ht', 'api.hu',
    'api.hv', 'api.hw', 'api.hx', 'api.hy', 'api.hypernova', 'api.hz', 'api.i',
    'api.ia', 'api.ib', 'api.ibm', 'api.ic', 'api.id', 'api.identity', 'api.idp',
    'api.ie', 'api.if', 'api.ig', 'api.ih', 'api.ii', 'api.ij', 'api.ik',
    'api.il', 'api.im', 'api.images', 'api.imail', 'api.imap', 'api.imap1',
    'api.imap3', 'api.imap3d', 'api.imapd', 'api.imaps', 'api.img', 'api.img1',
    'api.imgs', 'api.imogen', 'api.in', 'api.inmuebles', 'api.internal',
    'api.interno', 'api.intra', 'api.intranet', 'api.intranet1', 'api.io',
    'api.ip', 'api.ip6', 'api.ipsec', 'api.ipv6', 'api.iq', 'api.ir', 'api.irc',
    'api.ircd', 'api.is', 'api.isa', 'api.it', 'api.itunes', 'api.iu', 'api.iv',
    'api.iw', 'api.ix', 'api.iy', 'api.iz', 'api.j', 'api.ja', 'api.jabber',
    'api.jb', 'api.jc', 'api.jd', 'api.je', 'api.jenkins', 'api.jf', 'api.jg',
    'api.jh', 'api.ji', 'api.jira', 'api.jj', 'api.jk', 'api.jl', 'api.jm',
    'api.jn', 'api.jo', 'api.jp', 'api.jq', 'api.jr', 'api.js', 'api.jt',
    'api.ju', 'api.jupiter', 'api.jv', 'api.jw', 'api.jx', 'api.jy', 'api.jz',
    'api.k', 'api.k8s', 'api.ka', 'api.kb', 'api.kb1', 'api.kb2', 'api.kc',
    'api.kd', 'api.ke', 'api.kf', 'api.kg', 'api.kh', 'api.ki', 'api.kibana',
    'api.kj', 'api.kk', 'api.kl', 'api.km', 'api.kn', 'api.knowledgebase',
    'api.ko', 'api.kp', 'api.kq', 'api.kr', 'api.ks', 'api.kt', 'api.ku',
    'api.kubernetes', 'api.kv', 'api.kw', 'api.kx', 'api.ky', 'api.kz', 'api.l',
    'api.la', 'api.lab', 'api.laboratories', 'api.laboratorio', 'api.laboratory',
    'api.labs', 'api.lb', 'api.lc', 'api.ld', 'api.ldap', 'api.le', 'api.legacy',
    'api.lf', 'api.lg', 'api.lh', 'api.li', 'api.library', 'api.linode',
    'api.linux', 'api.lisa', 'api.live', 'api.live1', 'api.lj', 'api.lk',
    'api.ll', 'api.lm', 'api.ln', 'api.lo', 'api.localhost', 'api.log',
    'api.logging', 'api.login', 'api.logon', 'api.logs', 'api.logs1', 'api.lp',
    'api.lq', 'api.lr', 'api.ls', 'api.lt', 'api.lu', 'api.lv', 'api.lw',
    'api.lx', 'api.ly', 'api.lz', 'api.m', 'api.ma', 'api.magento', 'api.mail',
    'api.mailchimp', 'api.mailer', 'api.mailgate', 'api.mailgun',
    'api.management', 'api.manager', 'api.manual', 'api.marketing',
    'api.mastodon', 'api.mb', 'api.mc', 'api.md', 'api.me', 'api.media',
    'api.member', 'api.members', 'api.members-api', 'api.memcached',
    'api.mercury', 'api.messages', 'api.messaging', 'api.messenger', 'api.meta',
    'api.meta01', 'api.meta02', 'api.meta03', 'api.meta1', 'api.meta2',
    'api.meta3', 'api.metrics', 'api.metrics-api', 'api.metrics1', 'api.mf',
    'api.mg', 'api.mh', 'api.mi', 'api.miembros', 'api.minerva', 'api.mirror',
    'api.mirror1', 'api.mirrors', 'api.mj', 'api.mk', 'api.ml', 'api.mm',
    'api.mn', 'api.mo', 'api.mob', 'api.mobile', 'api.mongo', 'api.mongodb',
    'api.monitor', 'api.monitoring', 'api.moodle', 'api.movil', 'api.mp',
    'api.mq', 'api.mr', 'api.ms', 'api.msg', 'api.mssql', 'api.mt', 'api.mu',
    'api.mv', 'api.mw', 'api.mx', 'api.mx0', 'api.mx01', 'api.mx02', 'api.mx03',
    'api.mx1', 'api.mx2', 'api.mx3', 'api.my', 'api.mysql', 'api.mz', 'api.n',
    'api.na', 'api.nameserver', 'api.nb', 'api.nc', 'api.nd', 'api.ne',
    'api.nelson', 'api.neon', 'api.net', 'api.netlify', 'api.netmail',
    'api.news', 'api.nf', 'api.ng', 'api.nh', 'api.ni', 'api.nj', 'api.nk',
    'api.nl', 'api.nm', 'api.nn', 'api.no', 'api.nosql', 'api.novell', 'api.np',
    'api.nq', 'api.nr', 'api.ns', 'api.ns0', 'api.ns01', 'api.ns02', 'api.ns03',
    'api.ns1', 'api.ns2', 'api.ns3', 'api.ns4', 'api.nt', 'api.ntp', 'api.nu',
    'api.nv', 'api.nw', 'api.nx', 'api.ny', 'api.nz', 'api.o', 'api.oa',
    'api.oauth', 'api.ob', 'api.observability', 'api.observability-api',
    'api.oc', 'api.od', 'api.oe', 'api.of', 'api.og', 'api.oh', 'api.oi',
    'api.oj', 'api.ok', 'api.okta', 'api.ol', 'api.old', 'api.old1', 'api.om',
    'api.on', 'api.online', 'api.oo', 'api.op', 'api.openapi', 'api.oq',
    'api.or', 'api.ora', 'api.oracle', 'api.oraclecloud', 'api.origin',
    'api.origin1', 'api.origin2', 'api.os', 'api.osx', 'api.ot', 'api.ou',
    'api.ov', 'api.ovh', 'api.ow', 'api.owa', 'api.ox', 'api.oy', 'api.oz',
    'api.p', 'api.pa', 'api.partners', 'api.payment', 'api.payment-gateway',
    'api.payments', 'api.payments-api', 'api.payments-ui', 'api.payments1',
    'api.payments2', 'api.paymentsportal', 'api.paypal', 'api.pb', 'api.pc',
    'api.pcanywhere', 'api.pd', 'api.pe', 'api.pegasus', 'api.pendrell',
    'api.personal', 'api.pf', 'api.pg', 'api.ph', 'api.photo', 'api.photos',
    'api.pi', 'api.pj', 'api.pk', 'api.pl', 'api.platform', 'api.play', 'api.pm',
    'api.pn', 'api.po', 'api.pop', 'api.pop3', 'api.pop31', 'api.portal',
    'api.portal2', 'api.postgres', 'api.postgresql', 'api.postman',
    'api.postmaster', 'api.pp', 'api.ppp', 'api.pq', 'api.pr', 'api.pre-prod',
    'api.preprod', 'api.press', 'api.pressroom', 'api.private', 'api.prod',
    'api.production', 'api.profile', 'api.profiles', 'api.prometheus',
    'api.proxy', 'api.prueba', 'api.pruebas', 'api.ps', 'api.pt', 'api.pu',
    'api.pub', 'api.public', 'api.pv', 'api.pw', 'api.px', 'api.py', 'api.pz',
    'api.q', 'api.qa', 'api.qb', 'api.qc', 'api.qd', 'api.qe', 'api.qf',
    'api.qg', 'api.qh', 'api.qi', 'api.qj', 'api.qk', 'api.ql', 'api.qm',
    'api.qn', 'api.qo', 'api.qp', 'api.qq', 'api.qr', 'api.qs', 'api.qt',
    'api.qu', 'api.qv', 'api.qw', 'api.qx', 'api.qy', 'api.qz', 'api.r',
    'api.ra', 'api.rackspace', 'api.ras', 'api.rb', 'api.rc', 'api.rd', 'api.re',
    'api.redis', 'api.release', 'api.remote', 'api.reports', 'api.reports1',
    'api.research', 'api.resources', 'api.restricted', 'api.retail',
    'api.reverse-proxy', 'api.rf', 'api.rg', 'api.rh', 'api.ri', 'api.rj',
    'api.rk', 'api.rl', 'api.rm', 'api.rn', 'api.ro', 'api.robinhood',
    'api.router', 'api.rp', 'api.rq', 'api.rr', 'api.rs', 'api.rt', 'api.rtr',
    'api.ru', 'api.rv', 'api.rw', 'api.rx', 'api.ry', 'api.rz', 'api.s',
    'api.s3', 'api.s3-external', 'api.s3-us-west-2', 'api.s3-website', 'api.sa',
    'api.sales', 'api.salesforce', 'api.saml', 'api.sample', 'api.samples',
    'api.sandbox', 'api.sandbox1', 'api.sandbox2', 'api.sb', 'api.sc',
    'api.scaleway', 'api.sd', 'api.se', 'api.search', 'api.secure', 'api.seguro',
    'api.server', 'api.services', 'api.servicios', 'api.servidor', 'api.sf',
    'api.sftp', 'api.sg', 'api.sh', 'api.sharepoint', 'api.shop', 'api.shopify',
    'api.shopping', 'api.si', 'api.signin', 'api.signup', 'api.sip', 'api.sj',
    'api.sk', 'api.sl', 'api.sm', 'api.sms', 'api.smtp', 'api.smtp1', 'api.sn',
    'api.so', 'api.social', 'api.social-media', 'api.social1', 'api.socios',
    'api.solaris', 'api.soporte', 'api.sp', 'api.sq', 'api.sql', 'api.squirrel',
    'api.squirrelmail', 'api.sr', 'api.ss', 'api.ssh', 'api.ssh1', 'api.ssh2',
    'api.sso', 'api.st', 'api.staff', 'api.stage', 'api.staging', 'api.static',
    'api.static-01', 'api.static-02', 'api.static1', 'api.static2', 'api.stats',
    'api.status', 'api.status-api', 'api.status-check', 'api.statusapi',
    'api.statuscheck', 'api.statuspage', 'api.store', 'api.storefront',
    'api.stream', 'api.streaming', 'api.stripe', 'api.stun', 'api.su',
    'api.subscriptions', 'api.sun', 'api.support', 'api.support-api',
    'api.supportcenter', 'api.supportchat', 'api.supportportal', 'api.sv',
    'api.svn', 'api.sw', 'api.swagger', 'api.sx', 'api.sy', 'api.sz', 'api.t',
    'api.ta', 'api.tb', 'api.tc', 'api.td', 'api.te', 'api.test', 'api.testing',
    'api.tf', 'api.tftp', 'api.tg', 'api.th', 'api.ti', 'api.ticket',
    'api.ticketing', 'api.tickets', 'api.tienda', 'api.tj', 'api.tk', 'api.tl',
    'api.tm', 'api.tn', 'api.to', 'api.tp', 'api.tq', 'api.tr', 'api.try',
    'api.ts', 'api.tt', 'api.tu', 'api.tunnel', 'api.turn', 'api.tv', 'api.tw',
    'api.tx', 'api.ty', 'api.tz', 'api.u', 'api.ua', 'api.uat', 'api.ub',
    'api.uc', 'api.ud', 'api.ue', 'api.uf', 'api.ug', 'api.uh', 'api.ui',
    'api.uj', 'api.uk', 'api.ul', 'api.um', 'api.un', 'api.unix', 'api.uo',
    'api.up', 'api.updates', 'api.upload', 'api.upload1', 'api.upload2',
    'api.uploads', 'api.uq', 'api.ur', 'api.us', 'api.user', 'api.userapi',
    'api.users', 'api.users-api', 'api.ut', 'api.uu', 'api.uv', 'api.uw',
    'api.ux', 'api.uy', 'api.uz', 'api.v', 'api.va', 'api.vb', 'api.vc',
    'api.vd', 'api.ve', 'api.ventas', 'api.vercel', 'api.vf', 'api.vg', 'api.vh',
    'api.vi', 'api.video', 'api.virtual', 'api.vista', 'api.vj', 'api.vk',
    'api.vl', 'api.vm', 'api.vn', 'api.vnc', 'api.vo', 'api.voice', 'api.voip',
    'api.vp', 'api.vpn', 'api.vpn1', 'api.vpn2', 'api.vpn3', 'api.vpns',
    'api.vq', 'api.vr', 'api.vs', 'api.vt', 'api.vu', 'api.vv', 'api.vw',
    'api.vx', 'api.vy', 'api.vz', 'api.w', 'api.wa', 'api.wap', 'api.wb',
    'api.wc', 'api.wd', 'api.we', 'api.web', 'api.web0', 'api.web01',
    'api.web02', 'api.web03', 'api.web1', 'api.web2', 'api.web3', 'api.webadmin',
    'api.webct', 'api.webhook', 'api.webhooks', 'api.weblog', 'api.webmail',
    'api.webmaster', 'api.webmin', 'api.webrtc', 'api.wf', 'api.wg', 'api.wh',
    'api.wi', 'api.wiki', 'api.wiki1', 'api.wiki2', 'api.win', 'api.windows',
    'api.wj', 'api.wk', 'api.wl', 'api.wm', 'api.wn', 'api.wo', 'api.wordpress',
    'api.wordpress-site', 'api.wordpress1', 'api.wp', 'api.wq', 'api.wr',
    'api.ws', 'api.wt', 'api.wu', 'api.wv', 'api.ww', 'api.ww0', 'api.ww01',
    'api.ww02', 'api.ww03', 'api.ww1', 'api.ww2', 'api.ww3', 'api.www', 'api.wx',
    'api.wy', 'api.wz', 'api.x', 'api.xa', 'api.xanthus', 'api.xb', 'api.xc',
    'api.xd', 'api.xe', 'api.xf', 'api.xg', 'api.xh', 'api.xi', 'api.xj',
    'api.xk', 'api.xl', 'api.xm', 'api.xmpp', 'api.xn', 'api.xo', 'api.xp',
    'api.xq', 'api.xr', 'api.xs', 'api.xt', 'api.xu', 'api.xv', 'api.xw',
    'api.xx', 'api.xy', 'api.xz', 'api.y', 'api.ya', 'api.yb', 'api.yc',
    'api.yd', 'api.ye', 'api.yf', 'api.yg', 'api.yh', 'api.yi', 'api.yj',
    'api.yk', 'api.yl', 'api.ym', 'api.yn', 'api.yo', 'api.yp', 'api.yq',
    'api.yr', 'api.ys', 'api.yt', 'api.yu', 'api.yv', 'api.yw', 'api.yx',
    'api.yy', 'api.yz', 'api.z', 'api.za', 'api.zb', 'api.zc', 'api.zd',
    'api.ze', 'api.zendesk', 'api.zendesk1', 'api.zeus', 'api.zf', 'api.zg',
    'api.zh', 'api.zi', 'api.zj', 'api.zk', 'api.zl', 'api.zm', 'api.zn',
    'api.zo', 'api.zp', 'api.zq', 'api.zr', 'api.zs', 'api.zt', 'api.zu',
    'api.zv', 'api.zw', 'api.zx', 'api.zy', 'api.zz', 'api1', 'api1-01',
    'api1-02', 'api1-1', 'api1-2', 'api1-api', 'api1-app', 'api1-beta',
    'api1-dev', 'api1-internal', 'api1-prod', 'api1-srv', 'api1-stage',
    'api1-staging', 'api1-svc', 'api1-test', 'api1-web', 'api11', 'api12',
    'api13', 'api14', 'api15', 'api2', 'api2-01', 'api2-02', 'api2-1', 'api2-2',
    'api2-api', 'api2-app', 'api2-beta', 'api2-dev', 'api2-internal',
    'api2-prod', 'api2-srv', 'api2-stage', 'api2-staging', 'api2-svc',
    'api2-test', 'api2-web', 'api21', 'api22', 'api23', 'api24', 'api25', 'api3',
    'api4', 'api5', 'apiadmin', 'apiassets', 'apiauth', 'apibeta', 'apibilling',
    'apicdn', 'apicontrol', 'apidashboard', 'apidev', 'apideveloper', 'apidocs',
    'apifiles', 'apihelp', 'apilogin', 'apimanager', 'apimedia', 'apipayments',
    'apiportal', 'apiprod', 'apiproduction', 'apisecure', 'apishop',
    'apistaging', 'apistatic', 'apistatus', 'apistore', 'apisupport', 'apitest',
    'apiuploads', 'apollo-01', 'apollo-02', 'apollo-1', 'apollo-2', 'apollo-api',
    'apollo-app', 'apollo-beta', 'apollo-dev', 'apollo-internal', 'apollo-prod',
    'apollo-srv', 'apollo-stage', 'apollo-staging', 'apollo-svc', 'apollo-test',
    'apollo-web', 'apollo1', 'apollo2', 'apollo3', 'apollo4', 'apollo5',
    'app-01', 'app-02', 'app-1', 'app-2', 'app-ap-northeast', 'app-ap-southeast',
    'app-api', 'app-app', 'app-beta', 'app-dev', 'app-eu-central', 'app-eu-west',
    'app-internal', 'app-me-central', 'app-prod', 'app-sa-east', 'app-srv',
    'app-stage', 'app-staging', 'app-svc', 'app-test', 'app-us-central',
    'app-us-east', 'app-us-west', 'app-web', 'app.a', 'app.aa', 'app.ab',
    'app.ac', 'app.access', 'app.account', 'app.accounting', 'app.accounts',
    'app.ad', 'app.admin', 'app.admin-panel', 'app.admin2', 'app.administrator',
    'app.ae', 'app.af', 'app.ag', 'app.ah', 'app.ai', 'app.aix', 'app.aj',
    'app.ak', 'app.akamai', 'app.al', 'app.alpha', 'app.am', 'app.amazonaws',
    'app.an', 'app.analytics', 'app.analytics1', 'app.ao', 'app.ap', 'app.api',
    'app.api-admin', 'app.api-auth', 'app.api-console', 'app.api-docs',
    'app.api-v1', 'app.api-v2', 'app.api1', 'app.api2', 'app.apollo', 'app.app',
    'app.apps', 'app.appspot', 'app.appstore', 'app.aq', 'app.ar', 'app.archive',
    'app.archives', 'app.archivos', 'app.as', 'app.assets', 'app.at', 'app.au',
    'app.aula', 'app.aulas', 'app.auth', 'app.auth0', 'app.av', 'app.aw',
    'app.aws', 'app.ax', 'app.ay', 'app.ayuda', 'app.az', 'app.azure', 'app.b',
    'app.ba', 'app.backup', 'app.backup1', 'app.backups', 'app.bart', 'app.bb',
    'app.bc', 'app.bd', 'app.be', 'app.beta', 'app.bf', 'app.bg', 'app.bh',
    'app.bi', 'app.biblioteca', 'app.billing', 'app.billing-api',
    'app.billing-ui', 'app.billing1', 'app.billingportal', 'app.bitbucket',
    'app.bj', 'app.bk', 'app.bl', 'app.blackboard', 'app.blog', 'app.blogs',
    'app.bm', 'app.bn', 'app.bo', 'app.bounce', 'app.bounces', 'app.bp',
    'app.bq', 'app.br', 'app.bs', 'app.bsd', 'app.bt', 'app.bu', 'app.bv',
    'app.bw', 'app.bx', 'app.by', 'app.bz', 'app.c', 'app.ca', 'app.cache',
    'app.call', 'app.calls', 'app.canary', 'app.carro', 'app.cart', 'app.cas',
    'app.catalog', 'app.catalogo', 'app.catalogue', 'app.cb', 'app.cc', 'app.cd',
    'app.cdn', 'app.cdn-01', 'app.cdn-02', 'app.cdn-03', 'app.cdn-asia',
    'app.cdn-edge', 'app.cdn-eu', 'app.cdn-origin', 'app.cdn-uk', 'app.cdn-us',
    'app.cdn1', 'app.cdn2', 'app.cdnworks', 'app.ce', 'app.cf', 'app.cg',
    'app.ch', 'app.chat', 'app.chat1', 'app.checkout', 'app.checkout1',
    'app.checkout2', 'app.chimera', 'app.chronos', 'app.ci', 'app.cicd',
    'app.citrix', 'app.cj', 'app.ck', 'app.cl', 'app.classroom', 'app.clientes',
    'app.clients', 'app.cloud', 'app.cloudflare', 'app.cloudfront', 'app.cm',
    'app.cn', 'app.co', 'app.community', 'app.confluence', 'app.connect',
    'app.console', 'app.console1', 'app.console2', 'app.control',
    'app.control-panel', 'app.controller', 'app.correoweb', 'app.cp',
    'app.cpanel', 'app.cq', 'app.cr', 'app.crm', 'app.cs', 'app.csg', 'app.ct',
    'app.cu', 'app.customer', 'app.customers', 'app.cv', 'app.cw', 'app.cx',
    'app.cy', 'app.cz', 'app.d', 'app.da', 'app.data', 'app.database', 'app.db',
    'app.dbs', 'app.dc', 'app.dd', 'app.de', 'app.demo', 'app.demo1',
    'app.demon', 'app.demostration', 'app.descargas', 'app.dev', 'app.dev1',
    'app.dev2', 'app.develop', 'app.developer', 'app.developers',
    'app.developers-api', 'app.development', 'app.df', 'app.dg', 'app.dh',
    'app.di', 'app.diana', 'app.digitalocean', 'app.directory', 'app.directory1',
    'app.dj', 'app.dk', 'app.dl', 'app.dm', 'app.dmz', 'app.dn', 'app.dns',
    'app.do', 'app.docker', 'app.docs', 'app.docs-api', 'app.docs-site',
    'app.docs1', 'app.docs2', 'app.documentation', 'app.domain',
    'app.domain-controller', 'app.domaincontroller', 'app.download',
    'app.downloads', 'app.dp', 'app.dq', 'app.dr', 'app.ds', 'app.dt', 'app.du',
    'app.dv', 'app.dw', 'app.dx', 'app.dy', 'app.dz', 'app.e', 'app.ea',
    'app.eaccess', 'app.eb', 'app.ec', 'app.ed', 'app.edge', 'app.edge1',
    'app.ee', 'app.ef', 'app.eg', 'app.eh', 'app.ei', 'app.ej', 'app.ejemplo',
    'app.ejemplos', 'app.ek', 'app.el', 'app.elastic', 'app.em', 'app.email',
    'app.en', 'app.enrutador', 'app.eo', 'app.ep', 'app.eq', 'app.er', 'app.es',
    'app.et', 'app.eu', 'app.ev', 'app.eventos', 'app.events', 'app.events-api',
    'app.ew', 'app.ex', 'app.example', 'app.examples', 'app.exchange',
    'app.extranet', 'app.ey', 'app.ez', 'app.f', 'app.fa', 'app.fastly',
    'app.fb', 'app.fc', 'app.fd', 'app.fe', 'app.feed', 'app.ff', 'app.fg',
    'app.fh', 'app.fi', 'app.files', 'app.fileserver', 'app.fileserver1',
    'app.fileserver2', 'app.finance', 'app.firebase', 'app.firebaseapp',
    'app.firewall', 'app.firmware', 'app.fj', 'app.fk', 'app.fl', 'app.fm',
    'app.fn', 'app.fo', 'app.foro', 'app.foros', 'app.forum', 'app.forums',
    'app.fp', 'app.fq', 'app.fr', 'app.freebsd', 'app.fs', 'app.ft', 'app.ftp',
    'app.ftpd', 'app.ftps', 'app.fu', 'app.fv', 'app.fw', 'app.fx', 'app.fy',
    'app.fz', 'app.g', 'app.ga', 'app.galeria', 'app.gallery', 'app.gateway',
    'app.gateway-admin', 'app.gb', 'app.gc', 'app.gcp', 'app.gd', 'app.ge',
    'app.gf', 'app.gg', 'app.gh', 'app.gi', 'app.gilford', 'app.git',
    'app.github', 'app.gitlab', 'app.gj', 'app.gk', 'app.gl', 'app.gm', 'app.gn',
    'app.go', 'app.google', 'app.googleusercontent', 'app.gp', 'app.gq',
    'app.gr', 'app.grafana', 'app.groups', 'app.groupwise', 'app.gs', 'app.gt',
    'app.gu', 'app.guest', 'app.guia', 'app.guide', 'app.gv', 'app.gw', 'app.gx',
    'app.gy', 'app.gz', 'app.h', 'app.ha', 'app.hb', 'app.hc', 'app.hd',
    'app.he', 'app.health', 'app.healthcheck', 'app.healthz', 'app.heartbeat',
    'app.help', 'app.helpcenter', 'app.helpchat', 'app.helpdesk', 'app.hera',
    'app.heracles', 'app.hercules', 'app.heroku', 'app.hetzner', 'app.hf',
    'app.hg', 'app.hh', 'app.hi', 'app.hj', 'app.hk', 'app.hl', 'app.hm',
    'app.hn', 'app.ho', 'app.home', 'app.home2', 'app.homer', 'app.hooks',
    'app.hooks1', 'app.hotspot', 'app.hp', 'app.hq', 'app.hr', 'app.hs',
    'app.ht', 'app.hu', 'app.hv', 'app.hw', 'app.hx', 'app.hy', 'app.hypernova',
    'app.hz', 'app.i', 'app.ia', 'app.ib', 'app.ibm', 'app.ic', 'app.id',
    'app.identity', 'app.idp', 'app.ie', 'app.if', 'app.ig', 'app.ih', 'app.ii',
    'app.ij', 'app.ik', 'app.il', 'app.im', 'app.images', 'app.imail',
    'app.imap', 'app.imap1', 'app.imap3', 'app.imap3d', 'app.imapd', 'app.imaps',
    'app.img', 'app.img1', 'app.imgs', 'app.imogen', 'app.in', 'app.inmuebles',
    'app.internal', 'app.interno', 'app.intra', 'app.intranet', 'app.intranet1',
    'app.io', 'app.ip', 'app.ip6', 'app.ipsec', 'app.ipv6', 'app.iq', 'app.ir',
    'app.irc', 'app.ircd', 'app.is', 'app.isa', 'app.it', 'app.itunes', 'app.iu',
    'app.iv', 'app.iw', 'app.ix', 'app.iy', 'app.iz', 'app.j', 'app.ja',
    'app.jabber', 'app.jb', 'app.jc', 'app.jd', 'app.je', 'app.jenkins',
    'app.jf', 'app.jg', 'app.jh', 'app.ji', 'app.jira', 'app.jj', 'app.jk',
    'app.jl', 'app.jm', 'app.jn', 'app.jo', 'app.jp', 'app.jq', 'app.jr',
    'app.js', 'app.jt', 'app.ju', 'app.jupiter', 'app.jv', 'app.jw', 'app.jx',
    'app.jy', 'app.jz', 'app.k', 'app.k8s', 'app.ka', 'app.kb', 'app.kb1',
    'app.kb2', 'app.kc', 'app.kd', 'app.ke', 'app.kf', 'app.kg', 'app.kh',
    'app.ki', 'app.kibana', 'app.kj', 'app.kk', 'app.kl', 'app.km', 'app.kn',
    'app.knowledgebase', 'app.ko', 'app.kp', 'app.kq', 'app.kr', 'app.ks',
    'app.kt', 'app.ku', 'app.kubernetes', 'app.kv', 'app.kw', 'app.kx', 'app.ky',
    'app.kz', 'app.l', 'app.la', 'app.lab', 'app.laboratories',
    'app.laboratorio', 'app.laboratory', 'app.labs', 'app.lb', 'app.lc',
    'app.ld', 'app.ldap', 'app.le', 'app.legacy', 'app.lf', 'app.lg', 'app.lh',
    'app.li', 'app.library', 'app.linode', 'app.linux', 'app.lisa', 'app.live',
    'app.live1', 'app.lj', 'app.lk', 'app.ll', 'app.lm', 'app.ln', 'app.lo',
    'app.localhost', 'app.log', 'app.logging', 'app.login', 'app.logon',
    'app.logs', 'app.logs1', 'app.lp', 'app.lq', 'app.lr', 'app.ls', 'app.lt',
    'app.lu', 'app.lv', 'app.lw', 'app.lx', 'app.ly', 'app.lz', 'app.m',
    'app.ma', 'app.magento', 'app.mail', 'app.mailchimp', 'app.mailer',
    'app.mailgate', 'app.mailgun', 'app.management', 'app.manager', 'app.manual',
    'app.marketing', 'app.mastodon', 'app.mb', 'app.mc', 'app.md', 'app.me',
    'app.media', 'app.member', 'app.members', 'app.members-api', 'app.memcached',
    'app.mercury', 'app.messages', 'app.messaging', 'app.messenger', 'app.meta',
    'app.meta01', 'app.meta02', 'app.meta03', 'app.meta1', 'app.meta2',
    'app.meta3', 'app.metrics', 'app.metrics-api', 'app.metrics1', 'app.mf',
    'app.mg', 'app.mh', 'app.mi', 'app.miembros', 'app.minerva', 'app.mirror',
    'app.mirror1', 'app.mirrors', 'app.mj', 'app.mk', 'app.ml', 'app.mm',
    'app.mn', 'app.mo', 'app.mob', 'app.mobile', 'app.mongo', 'app.mongodb',
    'app.monitor', 'app.monitoring', 'app.moodle', 'app.movil', 'app.mp',
    'app.mq', 'app.mr', 'app.ms', 'app.msg', 'app.mssql', 'app.mt', 'app.mu',
    'app.mv', 'app.mw', 'app.mx', 'app.mx0', 'app.mx01', 'app.mx02', 'app.mx03',
    'app.mx1', 'app.mx2', 'app.mx3', 'app.my', 'app.mysql', 'app.mz', 'app.n',
    'app.na', 'app.nameserver', 'app.nb', 'app.nc', 'app.nd', 'app.ne',
    'app.nelson', 'app.neon', 'app.net', 'app.netlify', 'app.netmail',
    'app.news', 'app.nf', 'app.ng', 'app.nh', 'app.ni', 'app.nj', 'app.nk',
    'app.nl', 'app.nm', 'app.nn', 'app.no', 'app.nosql', 'app.novell', 'app.np',
    'app.nq', 'app.nr', 'app.ns', 'app.ns0', 'app.ns01', 'app.ns02', 'app.ns03',
    'app.ns1', 'app.ns2', 'app.ns3', 'app.ns4', 'app.nt', 'app.ntp', 'app.nu',
    'app.nv', 'app.nw', 'app.nx', 'app.ny', 'app.nz', 'app.o', 'app.oa',
    'app.oauth', 'app.ob', 'app.observability', 'app.observability-api',
    'app.oc', 'app.od', 'app.oe', 'app.of', 'app.og', 'app.oh', 'app.oi',
    'app.oj', 'app.ok', 'app.okta', 'app.ol', 'app.old', 'app.old1', 'app.om',
    'app.on', 'app.online', 'app.oo', 'app.op', 'app.openapi', 'app.oq',
    'app.or', 'app.ora', 'app.oracle', 'app.oraclecloud', 'app.origin',
    'app.origin1', 'app.origin2', 'app.os', 'app.osx', 'app.ot', 'app.ou',
    'app.ov', 'app.ovh', 'app.ow', 'app.owa', 'app.ox', 'app.oy', 'app.oz',
    'app.p', 'app.pa', 'app.partners', 'app.payment', 'app.payment-gateway',
    'app.payments', 'app.payments-api', 'app.payments-ui', 'app.payments1',
    'app.payments2', 'app.paymentsportal', 'app.paypal', 'app.pb', 'app.pc',
    'app.pcanywhere', 'app.pd', 'app.pe', 'app.pegasus', 'app.pendrell',
    'app.personal', 'app.pf', 'app.pg', 'app.ph', 'app.photo', 'app.photos',
    'app.pi', 'app.pj', 'app.pk', 'app.pl', 'app.platform', 'app.play', 'app.pm',
    'app.pn', 'app.po', 'app.pop', 'app.pop3', 'app.pop31', 'app.portal',
    'app.portal2', 'app.postgres', 'app.postgresql', 'app.postman',
    'app.postmaster', 'app.pp', 'app.ppp', 'app.pq', 'app.pr', 'app.pre-prod',
    'app.preprod', 'app.press', 'app.pressroom', 'app.private', 'app.prod',
    'app.production', 'app.profile', 'app.profiles', 'app.prometheus',
    'app.proxy', 'app.prueba', 'app.pruebas', 'app.ps', 'app.pt', 'app.pu',
    'app.pub', 'app.public', 'app.pv', 'app.pw', 'app.px', 'app.py', 'app.pz',
    'app.q', 'app.qa', 'app.qb', 'app.qc', 'app.qd', 'app.qe', 'app.qf',
    'app.qg', 'app.qh', 'app.qi', 'app.qj', 'app.qk', 'app.ql', 'app.qm',
    'app.qn', 'app.qo', 'app.qp', 'app.qq', 'app.qr', 'app.qs', 'app.qt',
    'app.qu', 'app.qv', 'app.qw', 'app.qx', 'app.qy', 'app.qz', 'app.r',
    'app.ra', 'app.rackspace', 'app.ras', 'app.rb', 'app.rc', 'app.rd', 'app.re',
    'app.redis', 'app.release', 'app.remote', 'app.reports', 'app.reports1',
    'app.research', 'app.resources', 'app.restricted', 'app.retail',
    'app.reverse-proxy', 'app.rf', 'app.rg', 'app.rh', 'app.ri', 'app.rj',
    'app.rk', 'app.rl', 'app.rm', 'app.rn', 'app.ro', 'app.robinhood',
    'app.router', 'app.rp', 'app.rq', 'app.rr', 'app.rs', 'app.rt', 'app.rtr',
    'app.ru', 'app.rv', 'app.rw', 'app.rx', 'app.ry', 'app.rz', 'app.s',
    'app.s3', 'app.s3-external', 'app.s3-us-west-2', 'app.s3-website', 'app.sa',
    'app.sales', 'app.salesforce', 'app.saml', 'app.sample', 'app.samples',
    'app.sandbox', 'app.sandbox1', 'app.sandbox2', 'app.sb', 'app.sc',
    'app.scaleway', 'app.sd', 'app.se', 'app.search', 'app.secure', 'app.seguro',
    'app.server', 'app.services', 'app.servicios', 'app.servidor', 'app.sf',
    'app.sftp', 'app.sg', 'app.sh', 'app.sharepoint', 'app.shop', 'app.shopify',
    'app.shopping', 'app.si', 'app.signin', 'app.signup', 'app.sip', 'app.sj',
    'app.sk', 'app.sl', 'app.sm', 'app.sms', 'app.smtp', 'app.smtp1', 'app.sn',
    'app.so', 'app.social', 'app.social-media', 'app.social1', 'app.socios',
    'app.solaris', 'app.soporte', 'app.sp', 'app.sq', 'app.sql', 'app.squirrel',
    'app.squirrelmail', 'app.sr', 'app.ss', 'app.ssh', 'app.ssh1', 'app.ssh2',
    'app.sso', 'app.st', 'app.staff', 'app.stage', 'app.staging', 'app.static',
    'app.static-01', 'app.static-02', 'app.static1', 'app.static2', 'app.stats',
    'app.status', 'app.status-api', 'app.status-check', 'app.statusapi',
    'app.statuscheck', 'app.statuspage', 'app.store', 'app.storefront',
    'app.stream', 'app.streaming', 'app.stripe', 'app.stun', 'app.su',
    'app.subscriptions', 'app.sun', 'app.support', 'app.support-api',
    'app.supportcenter', 'app.supportchat', 'app.supportportal', 'app.sv',
    'app.svn', 'app.sw', 'app.swagger', 'app.sx', 'app.sy', 'app.sz', 'app.t',
    'app.ta', 'app.tb', 'app.tc', 'app.td', 'app.te', 'app.test', 'app.testing',
    'app.tf', 'app.tftp', 'app.tg', 'app.th', 'app.ti', 'app.ticket',
    'app.ticketing', 'app.tickets', 'app.tienda', 'app.tj', 'app.tk', 'app.tl',
    'app.tm', 'app.tn', 'app.to', 'app.tp', 'app.tq', 'app.tr', 'app.try',
    'app.ts', 'app.tt', 'app.tu', 'app.tunnel', 'app.turn', 'app.tv', 'app.tw',
    'app.tx', 'app.ty', 'app.tz', 'app.u', 'app.ua', 'app.uat', 'app.ub',
    'app.uc', 'app.ud', 'app.ue', 'app.uf', 'app.ug', 'app.uh', 'app.ui',
    'app.uj', 'app.uk', 'app.ul', 'app.um', 'app.un', 'app.unix', 'app.uo',
    'app.up', 'app.updates', 'app.upload', 'app.upload1', 'app.upload2',
    'app.uploads', 'app.uq', 'app.ur', 'app.us', 'app.user', 'app.userapi',
    'app.users', 'app.users-api', 'app.ut', 'app.uu', 'app.uv', 'app.uw',
    'app.ux', 'app.uy', 'app.uz', 'app.v', 'app.va', 'app.vb', 'app.vc',
    'app.vd', 'app.ve', 'app.ventas', 'app.vercel', 'app.vf', 'app.vg', 'app.vh',
    'app.vi', 'app.video', 'app.virtual', 'app.vista', 'app.vj', 'app.vk',
    'app.vl', 'app.vm', 'app.vn', 'app.vnc', 'app.vo', 'app.voice', 'app.voip',
    'app.vp', 'app.vpn', 'app.vpn1', 'app.vpn2', 'app.vpn3', 'app.vpns',
    'app.vq', 'app.vr', 'app.vs', 'app.vt', 'app.vu', 'app.vv', 'app.vw',
    'app.vx', 'app.vy', 'app.vz', 'app.w', 'app.wa', 'app.wap', 'app.wb',
    'app.wc', 'app.wd', 'app.we', 'app.web', 'app.web0', 'app.web01',
    'app.web02', 'app.web03', 'app.web1', 'app.web2', 'app.web3', 'app.webadmin',
    'app.webct', 'app.webhook', 'app.webhooks', 'app.weblog', 'app.webmail',
    'app.webmaster', 'app.webmin', 'app.webrtc', 'app.wf', 'app.wg', 'app.wh',
    'app.wi', 'app.wiki', 'app.wiki1', 'app.wiki2', 'app.win', 'app.windows',
    'app.wj', 'app.wk', 'app.wl', 'app.wm', 'app.wn', 'app.wo', 'app.wordpress',
    'app.wordpress-site', 'app.wordpress1', 'app.wp', 'app.wq', 'app.wr',
    'app.ws', 'app.wt', 'app.wu', 'app.wv', 'app.ww', 'app.ww0', 'app.ww01',
    'app.ww02', 'app.ww03', 'app.ww1', 'app.ww2', 'app.ww3', 'app.www', 'app.wx',
    'app.wy', 'app.wz', 'app.x', 'app.xa', 'app.xanthus', 'app.xb', 'app.xc',
    'app.xd', 'app.xe', 'app.xf', 'app.xg', 'app.xh', 'app.xi', 'app.xj',
    'app.xk', 'app.xl', 'app.xm', 'app.xmpp', 'app.xn', 'app.xo', 'app.xp',
    'app.xq', 'app.xr', 'app.xs', 'app.xt', 'app.xu', 'app.xv', 'app.xw',
    'app.xx', 'app.xy', 'app.xz', 'app.y', 'app.ya', 'app.yb', 'app.yc',
    'app.yd', 'app.ye', 'app.yf', 'app.yg', 'app.yh', 'app.yi', 'app.yj',
    'app.yk', 'app.yl', 'app.ym', 'app.yn', 'app.yo', 'app.yp', 'app.yq',
    'app.yr', 'app.ys', 'app.yt', 'app.yu', 'app.yv', 'app.yw', 'app.yx',
    'app.yy', 'app.yz', 'app.z', 'app.za', 'app.zb', 'app.zc', 'app.zd',
    'app.ze', 'app.zendesk', 'app.zendesk1', 'app.zeus', 'app.zf', 'app.zg',
    'app.zh', 'app.zi', 'app.zj', 'app.zk', 'app.zl', 'app.zm', 'app.zn',
    'app.zo', 'app.zp', 'app.zq', 'app.zr', 'app.zs', 'app.zt', 'app.zu',
    'app.zv', 'app.zw', 'app.zx', 'app.zy', 'app.zz', 'app1', 'app2', 'app3',
    'app4', 'app5', 'apps', 'apps-01', 'apps-02', 'apps-1', 'apps-2', 'apps-api',
    'apps-app', 'apps-beta', 'apps-dev', 'apps-internal', 'apps-prod',
    'apps-srv', 'apps-stage', 'apps-staging', 'apps-svc', 'apps-test',
    'apps-web', 'apps1', 'apps2', 'apps3', 'apps4', 'apps5', 'appspot',
    'appspot-01', 'appspot-02', 'appspot-1', 'appspot-2', 'appspot-api',
    'appspot-app', 'appspot-beta', 'appspot-dev', 'appspot-internal',
    'appspot-prod', 'appspot-srv', 'appspot-stage', 'appspot-staging',
    'appspot-svc', 'appspot-test', 'appspot-web', 'appspot1', 'appspot2',
    'appspot3', 'appspot4', 'appspot5', 'appstore', 'appstore-01', 'appstore-02',
    'appstore-1', 'appstore-2', 'appstore-api', 'appstore-app', 'appstore-beta',
    'appstore-dev', 'appstore-internal', 'appstore-prod', 'appstore-srv',
    'appstore-stage', 'appstore-staging', 'appstore-svc', 'appstore-test',
    'appstore-web', 'appstore1', 'appstore2', 'appstore3', 'appstore4',
    'appstore5', 'aq-01', 'aq-02', 'aq-1', 'aq-2', 'aq-api', 'aq-app', 'aq-beta',
    'aq-dev', 'aq-internal', 'aq-prod', 'aq-srv', 'aq-stage', 'aq-staging',
    'aq-svc', 'aq-test', 'aq-web', 'aq1', 'aq2', 'aq3', 'aq4', 'aq5', 'ar-01',
    'ar-02', 'ar-1', 'ar-2', 'ar-api', 'ar-app', 'ar-beta', 'ar-dev',
    'ar-internal', 'ar-prod', 'ar-srv', 'ar-stage', 'ar-staging', 'ar-svc',
    'ar-test', 'ar-web', 'ar1', 'ar2', 'ar3', 'ar4', 'ar5', 'archive',
    'archive-01', 'archive-02', 'archive-1', 'archive-2', 'archive-api',
    'archive-app', 'archive-beta', 'archive-dev', 'archive-internal',
    'archive-prod', 'archive-srv', 'archive-stage', 'archive-staging',
    'archive-svc', 'archive-test', 'archive-web', 'archive1', 'archive10',
    'archive11', 'archive12', 'archive13', 'archive14', 'archive15', 'archive16',
    'archive17', 'archive18', 'archive19', 'archive2', 'archive20', 'archive21',
    'archive22', 'archive23', 'archive24', 'archive25', 'archive26', 'archive27',
    'archive28', 'archive29', 'archive3', 'archive30', 'archive31', 'archive32',
    'archive33', 'archive34', 'archive35', 'archive36', 'archive37', 'archive38',
    'archive39', 'archive4', 'archive40', 'archive41', 'archive42', 'archive43',
    'archive44', 'archive45', 'archive46', 'archive47', 'archive48', 'archive49',
    'archive5', 'archive6', 'archive7', 'archive8', 'archive9', 'archives',
    'archives-01', 'archives-02', 'archives-1', 'archives-2', 'archives-api',
    'archives-app', 'archives-beta', 'archives-dev', 'archives-internal',
    'archives-prod', 'archives-srv', 'archives-stage', 'archives-staging',
    'archives-svc', 'archives-test', 'archives-web', 'archives1', 'archives2',
    'archives3', 'archives4', 'archives5', 'archivos-01', 'archivos-02',
    'archivos-1', 'archivos-2', 'archivos-api', 'archivos-app', 'archivos-beta',
    'archivos-dev', 'archivos-internal', 'archivos-prod', 'archivos-srv',
    'archivos-stage', 'archivos-staging', 'archivos-svc', 'archivos-test',
    'archivos-web', 'archivos1', 'archivos2', 'archivos3', 'archivos4',
    'archivos5', 'as-01', 'as-02', 'as-1', 'as-2', 'as-api', 'as-app', 'as-beta',
    'as-dev', 'as-internal', 'as-prod', 'as-srv', 'as-stage', 'as-staging',
    'as-svc', 'as-test', 'as-web', 'as1', 'as2', 'as3', 'as4', 'as5', 'assets',
    'assets-01', 'assets-02', 'assets-1', 'assets-2', 'assets-admin',
    'assets-api', 'assets-app', 'assets-auth', 'assets-beta', 'assets-billing',
    'assets-cdn', 'assets-control', 'assets-dashboard', 'assets-dev',
    'assets-developer', 'assets-docs', 'assets-files', 'assets-help',
    'assets-internal', 'assets-login', 'assets-manager', 'assets-media',
    'assets-payments', 'assets-portal', 'assets-prod', 'assets-production',
    'assets-secure', 'assets-shop', 'assets-srv', 'assets-stage',
    'assets-staging', 'assets-static', 'assets-status', 'assets-store',
    'assets-support', 'assets-svc', 'assets-test', 'assets-uploads',
    'assets-web', 'assets.admin', 'assets.api', 'assets.auth', 'assets.beta',
    'assets.billing', 'assets.cdn', 'assets.control', 'assets.dashboard',
    'assets.dev', 'assets.developer', 'assets.docs', 'assets.files',
    'assets.help', 'assets.login', 'assets.manager', 'assets.media',
    'assets.payments', 'assets.portal', 'assets.prod', 'assets.production',
    'assets.secure', 'assets.shop', 'assets.staging', 'assets.static',
    'assets.status', 'assets.store', 'assets.support', 'assets.test',
    'assets.uploads', 'assets1', 'assets2', 'assets3', 'assets4', 'assets5',
    'assetsadmin', 'assetsapi', 'assetsauth', 'assetsbeta', 'assetsbilling',
    'assetscdn', 'assetscontrol', 'assetsdashboard', 'assetsdev',
    'assetsdeveloper', 'assetsdocs', 'assetsfiles', 'assetshelp', 'assetslogin',
    'assetsmanager', 'assetsmedia', 'assetspayments', 'assetsportal',
    'assetsprod', 'assetsproduction', 'assetssecure', 'assetsshop',
    'assetsstaging', 'assetsstatic', 'assetsstatus', 'assetsstore',
    'assetssupport', 'assetstest', 'assetsuploads', 'at-01', 'at-02', 'at-1',
    'at-2', 'at-api', 'at-app', 'at-beta', 'at-dev', 'at-internal', 'at-prod',
    'at-srv', 'at-stage', 'at-staging', 'at-svc',
}

# --------------------------------------------------------------------

def fqdn(label: str, parent: str) -> str:
    return f"{label.strip('.').lower()}.{parent.strip('.').lower()}"

def make_resolver(ns: str, timeout: float) -> aresolver.Resolver:
    r = aresolver.Resolver(configure=False)
    r.nameservers = [ns]
    r.timeout = timeout
    r.lifetime = timeout
    r.retry_servfail = True
    return r

class DynamicSemaphore:
    def __init__(self, initial: int):
        self._max = max(1, int(initial))
        self._sem = asyncio.Semaphore(self._max)
        self._lock = asyncio.Lock()

    @property
    def limit(self) -> int:
        return self._max

    async def set_limit(self, new_limit: int):
        new_limit = max(1, int(new_limit))
        async with self._lock:
            if new_limit == self._max:
                return
            delta = new_limit - self._max
            self._max = new_limit
            if delta > 0:
                for _ in range(delta):
                    self._sem.release()
            else:
                for _ in range(-delta):
                    await self._sem.acquire()

    async def acquire(self):
        await self._sem.acquire()

    def release(self):
        self._sem.release()

class Telemetry:
    def __init__(self):
        self.samples = deque(maxlen=METRICS_WINDOW)
        self.counts = defaultdict(int)
        self.lock = asyncio.Lock()

    async def record(self, lat_ms: float, outcome: str):
        async with self.lock:
            self.samples.append((lat_ms, outcome))
            self.counts[outcome] += 1

    async def snapshot(self):
        async with self.lock:
            data = list(self.samples)
            counts = dict(self.counts)
        if not data:
            return {
                'p50': None, 'p90': None, 'success': 0, 'timeout': 0, 'error': 0,
                'total': 0, 'success_rate': 0.0, 'timeout_rate': 0.0
            }
        lats = sorted(x for x, _ in data)
        n = len(lats)
        def q(p):
            i = min(n-1, max(0, int(p*(n-1))))
            return lats[i]
        total = len(data)
        success = counts.get('success', 0)
        timeout = counts.get('timeout', 0)
        error   = counts.get('error', 0)
        return {
            'p50': q(0.50), 'p90': q(0.90),
            'success': success, 'timeout': timeout, 'error': error,
            'total': total,
            'success_rate': success/total if total else 0.0,
            'timeout_rate': timeout/total if total else 0.0,
        }

telemetry = Telemetry()

RES_FAIL_LIMIT = 5
RES_COOLDOWN = 30
resolver_state: Dict[int, Dict[str, float]] = {}

def init_resolver_state(n: int):
    global resolver_state
    resolver_state = {i: {'fails': 0, 'cool_until': 0.0} for i in range(n)}

def mark_resolver(idx: int, ok: bool):
    st = resolver_state[idx]
    if ok:
        st['fails'] = max(0, st['fails'] - 1)
    else:
        st['fails'] += 1
        if st['fails'] >= RES_FAIL_LIMIT:
            st['cool_until'] = monotonic() + RES_COOLDOWN
            st['fails'] = 0

def pick_resolver_index(name: str, n: int) -> int:
    return hash(name) % n

def pick_healthy_resolver(name: str, resolvers: List[aresolver.Resolver]) -> int:
    start = pick_resolver_index(name, len(resolvers))
    now = monotonic()
    for off in range(len(resolvers)):
        idx = (start + off) % len(resolvers)
        st = resolver_state[idx]
        if now >= st['cool_until']:
            return idx
    return start

async def timed_resolve(fq: str, resolver: aresolver.Resolver, qtype: str, lifetime: float):
    t0 = time.perf_counter()
    try:
        ans = await asyncio.wait_for(
            resolver.resolve(fq, qtype, lifetime=lifetime),
            timeout=lifetime + 0.5
        )
        lat = (time.perf_counter() - t0) * 1000
        await telemetry.record(lat, 'success')
        if qtype in ('A', 'AAAA'):
            return [getattr(rd, 'address', None) for rd in ans if getattr(rd, 'address', None)]
        return []
    except (dresolver.NXDOMAIN, dresolver.NoAnswer):
        lat = (time.perf_counter() - t0) * 1000
        await telemetry.record(lat, 'success')
        return []
    except (asyncio.TimeoutError, dns.exception.Timeout, dresolver.LifetimeTimeout, dresolver.NoNameservers):
        lat = (time.perf_counter() - t0) * 1000
        await telemetry.record(lat, 'timeout')
        return []
    except Exception:
        lat = (time.perf_counter() - t0) * 1000
        await telemetry.record(lat, 'error')
        return []

async def resolve_one(name: str, resolvers: List[aresolver.Resolver], timeout: float) -> List[str]:
    idx = pick_healthy_resolver(name, resolvers)
    r = resolvers[idx]
    addrs = await timed_resolve(name, r, 'A', timeout)
    ok = addrs is not None
    mark_resolver(idx, ok)
    if addrs:
        return sorted(set(addrs))
    if monotonic() < resolver_state[idx]['cool_until']:
        idx = pick_healthy_resolver(name, resolvers)
        r = resolvers[idx]
    addrs = await timed_resolve(name, r, 'AAAA', timeout)
    mark_resolver(idx, addrs is not None)
    return sorted(set(addrs)) if addrs else []

async def detect_wildcard(parent: str, resolvers: List[aresolver.Resolver],
                          timeout: float, probes: int = 2) -> Set[str]:
    ips: Set[str] = set()
    tasks = []
    for _ in range(max(1, probes)):
        label = str(random.randint(10**9, 10**10 - 1))
        tasks.append(asyncio.create_task(resolve_one(fqdn(label, parent), resolvers, timeout)))
    if tasks:
        done, _ = await asyncio.wait(tasks)
        for fut in done:
            try:
                for ip in fut.result():
                    ips.add(ip)
            except Exception:
                pass
    return ips

def fqdn(label: str, parent: str) -> str:
    return f"{label.strip('.').lower()}.{parent.strip('.').lower()}"

async def worker(q: asyncio.Queue, parent: str, limiter,
                 resolvers: List[aresolver.Resolver], timeout_ref: dict,
                 wildcard_ips: Set[str], progress: dict):
    while True:
        label = await q.get()
        try:
            if label is None:
                return
            # count attempted resolutions (labels taken from the queue)
            progress['attempted'] += 1
            name = fqdn(label, parent)
            await limiter.acquire()
            try:
                addrs = await resolve_one(name, resolvers, timeout_ref['value'])
            finally:
                limiter.release()
            if addrs and (not wildcard_ips or not all(a in wildcard_ips for a in addrs)):
                progress['found'] += 1
                print(name, flush=True)
            progress['processed'] += 1
        except Exception as e:
            sys.stderr.write(f"[warn] worker error: {e}\n"); sys.stderr.flush()
        finally:
            q.task_done()

async def adjuster_task(limiter, resolvers: List[aresolver.Resolver],
                        queue: asyncio.Queue, timeout_ref: dict):
    while True:
        await asyncio.sleep(ADJUST_PERIOD)
        snap = await telemetry.snapshot()
        p90 = snap['p90']
        succ = snap['success_rate']
        to_rate = snap['timeout_rate']
        total = snap['total']
        qsize = queue.qsize()
        old_limit = limiter.limit
        new_limit = old_limit

        if p90 is not None:
            if total >= RAMP_MIN_SAMPLES and succ >= 0.90 and p90 <= TARGET_P90_MS and qsize > 0:
                new_limit = int(min(CONC_MAX, max(CONC_MIN, round(old_limit * 1.10))))
            if to_rate >= 0.08 or (p90 > TARGET_P90_MS and total >= 50):
                new_limit = int(max(CONC_MIN, round(old_limit * 0.70)))

        if new_limit != old_limit:
            await limiter.set_limit(new_limit)

        if p90 is not None and total >= 50:
            new_timeout = max(TIMEOUT_MIN, min(TIMEOUT_MAX, (p90 / 1000.0) * 1.5))
            if abs(new_timeout - timeout_ref['value']) >= 0.2:
                timeout_ref['value'] = new_timeout
                for r in resolvers:
                    r.timeout = new_timeout
                    r.lifetime = new_timeout

        sys.stderr.write(
            f"[tune] conc={limiter.limit} p90={(p90 if p90 is not None else -1):.0f}ms "
            f"success={succ:.0%} timeouts={to_rate:.0%} samples={total} "
            f"q={qsize} timeout={timeout_ref['value']:.1f}s\n"
        ); sys.stderr.flush()

if len(sys.argv) < 2:
    sys.stderr.write('Parent domain required, e.g., python dnsmap_async_tuned_full.py example.com\n')
    sys.exit(2)
PARENT = sys.argv[1].strip().lower()
if '.' not in PARENT:
    sys.stderr.write('Parent domain must be like example.com\n')
    sys.exit(2)

async def main():
    resolvers = [make_resolver(ns, INITIAL_TIMEOUT) for ns in DEFAULT_NAMESERVERS]
    init_resolver_state(len(resolvers))
    start_time = time.perf_counter()


    wildcard_ips = await detect_wildcard(PARENT, resolvers, INITIAL_TIMEOUT, probes=2)
    if wildcard_ips:
        sys.stderr.write(f"[info] wildcard detected; ignoring IPs: {', '.join(sorted(wildcard_ips))}\n")
        sys.stderr.flush()

    q = asyncio.Queue()
    limiter = DynamicSemaphore(INITIAL_CONCURRENCY)
    timeout_ref = {'value': INITIAL_TIMEOUT}
    progress = {'processed': 0, 'attempted': 0, 'found': 0}

    for s in subs_set:
        await q.put(str(s).strip().lower())

    workers = [
        asyncio.create_task(worker(q, PARENT, limiter, resolvers, timeout_ref, wildcard_ips, progress))
        for _ in range(INITIAL_CONCURRENCY)
    ]

    tuner = asyncio.create_task(adjuster_task(limiter, resolvers, q, timeout_ref))

    await q.join()

    for _ in workers:
        await q.put(None)
    await asyncio.gather(*workers, return_exceptions=True)
    tuner.cancel()
    try:
        await tuner
    except asyncio.CancelledError:
        pass

    # --- stats ---
    end_time = time.perf_counter()
    duration = max(1e-6, end_time - start_time)
    attempted = progress.get("attempted", 0)
    found = progress.get("found", 0)
    avg_per_sec = attempted / duration if duration > 0 else float(attempted)
    sys.stderr.write(f"[stats] duration={duration:.2f}s attempted={attempted} found={found} avg_per_sec={avg_per_sec:.2f}\n")
    sys.stderr.flush()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
