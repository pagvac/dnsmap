import sys, socket
from random import randint, randrange


if len(sys. argv) == 1:
    print("parent domain needed. e.g.:\n" + "python dnsmap.py github.com")
    sys.exit(1)

# returns IPs to avoid when wilcard record is on
# or False if no wildcard record is detected
def is_wildcard_record_on(parent_domain):
    random_domain = str(randint(1000000000,9999999999)) + '.' + parent_domain
    try:
        ip_addresses = socket.gethostbyname_ex(random_domain)
        if ip_addresses[2]:
            return ip_addresses[2]
    except:
        return False
	
subs_set = {
    "a",
    "aa",
    "ab",
    "ac",
    "access",
    "accounting",
    "accounts",
    "ad",
    "admin",
    "administrator",
    "ae",
    "af",
    "ag",
    "ah",
    "ai",
    "aix",
    "aj",
    "ak",
    "al",
    "am",
    "an",
    "ao",
    "ap",
    "api",
    "apollo",
    "aq",
    "ar",
    "archivos",
    "as",
    "at",
    "au",
    "aula",
    "aulas",
    "av",
    "aw",
    "ax",
    "ay",
    "ayuda",
    "az",
    "b",
    "ba",
    "backup",
    "backups",
    "bart",
    "bb",
    "bc",
    "bd",
    "be",
    "beta",
    "bf",
    "bg",
    "bh",
    "bi",
    "biblioteca",
    "billing",
    "bj",
    "bk",
    "bl",
    "blackboard",
    "blog",
    "blogs",
    "bm",
    "bn",
    "bo",
    "bp",
    "bq",
    "br",
    "bs",
    "bsd",
    "bt",
    "bu",
    "bv",
    "bw",
    "bx",
    "by",
    "bz",
    "c",
    "ca",
    "carro",
    "cart",
    "cas",
    "catalog",
    "catalogo",
    "catalogue",
    "cb",
    "cc",
    "cd",
    "ce",
    "cf",
    "cg",
    "ch",
    "chat",
    "chimera",
    "chronos", # time server?
    "ci",
    "cicd",
    "citrix",
    "cj",
    "ck",
    "cl",
    "classroom",
    "clientes",
    "clients",
    "cm",
    "cn",
    "co",
    "connect",
    "controller",
    "correoweb",
    "cp",
    "cpanel",
    "cq",
    "cr",
    "cs",
    "csg",
    "ct",
    "cu",
    "customers",
    "cv",
    "cw",
    "cx",
    "cy",
    "cz",
    "d",
    "da",
    "data",
    "db",
    "dbs",
    "dc", # domain controller?
    "dd",
    "de",
    "demo",
    "demon",
    "demostration",
    "descargas",
    "develop",
    "developers",
    "development",
    "df",
    "dg",
    "dh",
    "di",
    "diana",
    "directory",
    "dj",
    "dk",
    "dl",
    "dm",
    "dmz",
    "dn",
    "do",
    "docker",
    "docs",
    "domain",
    "domaincontroller",
    "domain-controller",
    "download",
    "downloads",
    "dp",
    "dq",
    "dr",
    "ds",
    "dt",
    "du",
    "dv",
    "dw",
    "dx",
    "dy",
    "dz",
    "e",
    "ea",
    "eaccess",
    "eb",
    "ec",
    "ed",
    "ee",
    "ef",
    "eg",
    "eh",
    "ei",
    "ej",
    "ejemplo",
    "ejemplos",
    "ek",
    "el",
    "em",
    "email",
    "en",
    "enrutador",
    "eo",
    "ep",
    "eq",
    "er",
    "es",
    "et",
    "eu",
    "ev",
    "eventos",
    "events",
    "ew",
    "ex",
    "example",
    "examples",
    "exchange",
    "extranet",
    "ey",
    "ez",
    "f",
    "fa",
    "fb",
    "fc",
    "fd",
    "fe",
    "feed",
    "ff",
    "fg",
    "fh",
    "fi",
    "files",
    "finance",
    "firewall",
    "firmware",
    "fj",
    "fk",
    "fl",
    "fm",
    "fn",
    "fo",
    "foro",
    "foros",
    "forum",
    "forums",
    "fp",
    "fq",
    "fr",
    "freebsd",
    "fs",
    "ft",
    "ftp",
    "ftpd",
    "fu",
    "fv",
    "fw",
    "fx",
    "fy",
    "fz",
    "g",
    "ga",
    "galeria",
    "gallery",
    "gateway",
    "gb",
    "gc",
    "gd",
    "ge",
    "gf",
    "gg",
    "gh",
    "gi",
    "gilford",
    "gj",
    "gk",
    "gl",
    "gm",
    "gn",
    "go",
    "gp",
    "gq",
    "gr",
    "groups",
    "groupwise",
    "gs",
    "gt",
    "gu",
    "guest",
    "guia",
    "guide",
    "gv",
    "gw",
    "gx",
    "gy",
    "gz",
    "h",
    "ha",
    "hb",
    "hc",
    "hd",
    "he",
    "help",
    "helpdesk",
    "hera",
    "heracles",
    "hercules",
    "hf",
    "hg",
    "hh",
    "hi",
    "hj",
    "hk",
    "hl",
    "hm",
    "hn",
    "ho",
    "home",
    "homer",
    "hotspot",
    "hp",
    "hq",
    "hr",
    "hs",
    "ht",
    "hu",
    "hv",
    "hw",
    "hx",
    "hy",
    "hypernova",
    "hz",
    "i",
    "ia",
    "ib",
    "ic",
    "id",
    "ie",
    "if",
    "ig",
    "ih",
    "ii",
    "ij",
    "ik",
    "il",
    "im",
    "images",
    "imail",
    "imap",
    "imap3",
    "imap3d",
    "imapd",
    "imaps",
    "imgs",
    "imogen",
    "in",
    "inmuebles",
    "internal",
    "interno",
    "intranet",
    "io",
    "ip",
    "ip6",
    "ipsec",
    "ipv6",
    "iq",
    "ir",
    "irc",
    "ircd",
    "is",
    "isa", # ISA proxy?
    "it",
    "iu",
    "iv",
    "iw",
    "ix",
    "iy",
    "iz",
    "j",
    "ja",
    "jabber",
    "jb",
    "jc",
    "jd",
    "je",
    "jenkins",
    "jf",
    "jg",
    "jh",
    "ji",
    "jj",
    "jk",
    "jl",
    "jm",
    "jn",
    "jo",
    "jp",
    "jq",
    "jr",
    "js",
    "jt",
    "ju",
    "jupiter",
    "jv",
    "jw",
    "jx",
    "jy",
    "jz",
    "k",
    "k8s",
    "ka",
    "kb",
    "kc",
    "kd",
    "ke",
    "kf",
    "kg",
    "kh",
    "ki",
    "kj",
    "kk",
    "kl",
    "km",
    "kn",
    "ko",
    "kp",
    "kq",
    "kr",
    "ks",
    "kt",
    "ku",
    "kv",
    "kw",
    "kx",
    "ky",
    "kz",
    "l",
    "la",
    "lab",
    "laboratories",
    "laboratorio",
    "laboratory",
    "labs",
    "lb",
    "lc",
    "ld",
    "le",
    "lf",
    "lg",
    "lh",
    "li",
    "library",
    "linux",
    "lisa",
    "lj",
    "lk",
    "ll",
    "lm",
    "ln",
    "lo",
    "localhost",
    "log",
    "login",
    "logon",
    "logs",
    "lp",
    "lq",
    "lr",
    "ls",
    "lt",
    "lu",
    "lv",
    "lw",
    "lx",
    "ly",
    "lz",
    "m",
    "ma",
    "mail",
    "mailgate",
    "manager",
    "manual",
    "marketing",
    "mb",
    "mc",
    "md",
    "me",
    "media",
    "member",
    "members",
    "mercury", # MX server?
    "meta",
    "meta01",
    "meta02",
    "meta03",
    "meta1",
    "meta2",
    "meta3",
    "mf",
    "mg",
    "mh",
    "mi",
    "miembros",
    "minerva",
    "mj",
    "mk",
    "ml",
    "mm",
    "mn",
    "mo",
    "mob",
    "mobile",
    "moodle",
    "movil",
    "mp",
    "mq",
    "mr",
    "ms",
    "mssql",
    "mt",
    "mu",
    "mv",
    "mw",
    "mx",
    "mx0",
    "mx01",
    "mx02",
    "mx03",
    "mx1",
    "mx2",
    "mx3",
    "my",
    "mysql",
    "mz",
    "n",
    "na",
    "nb",
    "nc",
    "nd",
    "ne",
    "nelson",
    "neon",
    "net",
    "netmail",
    "news",
    "nf",
    "ng",
    "nh",
    "ni",
    "nj",
    "nk",
    "nl",
    "nm",
    "nn",
    "no",
    "novell",
    "np",
    "nq",
    "nr",
    "ns",
    "ns0",
    "ns01",
    "ns02",
    "ns03",
    "ns1",
    "ns2",
    "ns3",
    "nt",
    "ntp",
    "nu",
    "nv",
    "nw",
    "nx",
    "ny",
    "nz",
    "o",
    "oa",
    "oauth",
    "ob",
    "oc",
    "od",
    "oe",
    "of",
    "og",
    "oh",
    "oi",
    "oj",
    "ok",
    "okta",
    "ol",
    "om",
    "on",
    "online",
    "oo",
    "op",
    "oq",
    "or",
    "ora",
    "oracle",
    "os",
    "osx",
    "ot",
    "ou",
    "ov",
    "ow",
    "owa",
    "ox",
    "oy",
    "oz",
    "p",
    "pa",
    "partners",
    "pb",
    "pc",
    "pcanywhere",
    "pd",
    "pe",
    "pegasus",
    "pendrell",
    "personal",
    "pf",
    "pg",
    "ph",
    "photo",
    "photos",
    "pi",
    "pj",
    "pk",
    "pl",
    "platform",
    "pm",
    "pn",
    "po",
    "pop",
    "pop3",
    "portal",
    "postgresql",
    "postman",
    "postmaster",
    "pp", # preprod?
    "ppp",
    "pq",
    "pr",
    "preprod",
    "pre-prod",
    "private",
    "prod",
    "proxy",
    "prueba",
    "pruebas",
    "ps",
    "pt",
    "pu",
    "pub",
    "public",
    "pv",
    "pw",
    "px",
    "py",
    "pz",
    "q",
    "qa",
    "qb",
    "qc",
    "qd",
    "qe",
    "qf",
    "qg",
    "qh",
    "qi",
    "qj",
    "qk",
    "ql",
    "qm",
    "qn",
    "qo",
    "qp",
    "qq",
    "qr",
    "qs",
    "qt",
    "qu",
    "qv",
    "qw",
    "qx",
    "qy",
    "qz",
    "r",
    "ra",
    "ras",
    "rb",
    "rc",
    "rd",
    "re",
    "remote",
    "reports",
    "research",
    "resources",
    "restricted",
    "rf",
    "rg",
    "rh",
    "ri",
    "rj",
    "rk",
    "rl",
    "rm",
    "rn",
    "ro",
    "robinhood",
    "router",
    "rp",
    "rq",
    "rr",
    "rs",
    "rt",
    "rtr",
    "ru",
    "rv",
    "rw",
    "rx",
    "ry",
    "rz",
    "s",
    "sa",
    "sales",
    "sample",
    "samples",
    "sandbox",
    "sb",
    "sc",
    "sd",
    "se",
    "search",
    "secure",
    "seguro",
    "server",
    "services",
    "servicios",
    "servidor",
    "sf",
    "sg",
    "sh",
    "sharepoint",
    "shop",
    "shopping",
    "si",
    "sj",
    "sk",
    "sl",
    "sm",
    "sms",
    "smtp",
    "sn",
    "so",
    "social",
    "socios",
    "solaris",
    "soporte",
    "sp", # sharepoint?
    "sq",
    "sql",
    "squirrel",
    "squirrelmail",
    "sr",
    "ss",
    "ssh",
    "sso",
    "st",
    "staff",
    "staging",
    "stats",
    "status",
    "su",
    "sun",
    "support",
    "sv",
    "sw",
    "sx",
    "sy",
    "sz",
    "t",
    "ta",
    "tb",
    "tc",
    "td",
    "te",
    "test",
    "tf",
    "tftp",
    "tg",
    "th",
    "ti",
    "tienda",
    "tj",
    "tk",
    "tl",
    "tm",
    "tn",
    "to",
    "tp",
    "tq",
    "tr",
    "ts",
    "tt",
    "tu",
    "tunnel",
    "tv",
    "tw",
    "tx",
    "ty",
    "tz",
    "u",
    "ua",
    "uat",
    "ub",
    "uc",
    "ud",
    "ue",
    "uf",
    "ug",
    "uh",
    "ui",
    "uj",
    "uk",
    "ul",
    "um",
    "un",
    "unix",
    "uo",
    "up",
    "updates",
    "upload",
    "uploads",
    "uq",
    "ur",
    "us",
    "ut",
    "uu",
    "uv",
    "uw",
    "ux",
    "uy",
    "uz",
    "v",
    "va",
    "vb",
    "vc",
    "vd",
    "ve",
    "ventas",
    "vf",
    "vg",
    "vh",
    "vi",
    "virtual",
    "vista",
    "vj",
    "vk",
    "vl",
    "vm",
    "vn",
    "vnc",
    "vo",
    "vp",
    "vpn",
    "vpn1",
    "vpn2",
    "vpn3",
    "vq",
    "vr",
    "vs",
    "vt",
    "vu",
    "vv",
    "vw",
    "vx",
    "vy",
    "vz",
    "w",
    "wa",
    "wap",
    "wb",
    "wc",
    "wd",
    "we",
    "web",
    "web0",
    "web01",
    "web02",
    "web03",
    "web1",
    "web2",
    "web3",
    "webadmin",
    "webct",
    "weblog",
    "webmail",
    "webmaster",
    "webmin",
    "wf",
    "wg",
    "wh",
    "wi",
    "win",
    "windows",
    "wj",
    "wk",
    "wl",
    "wm",
    "wn",
    "wo",
    "wp",
    "wq",
    "wr",
    "ws",
    "wt",
    "wu",
    "wv",
    "ww",
    "ww0",
    "ww01",
    "ww02",
    "ww03",
    "ww1",
    "ww2",
    "ww3",
    "www",
    "www0",
    "www01",
    "www02",
    "www03",
    "www1",
    "www2",
    "www3",
    "wx",
    "wy",
    "wz",
    "x",
    "xa",
    "xanthus",
    "xb",
    "xc",
    "xd",
    "xe",
    "xf",
    "xg",
    "xh",
    "xi",
    "xj",
    "xk",
    "xl",
    "xm",
    "xn",
    "xo",
    "xp",
    "xq",
    "xr",
    "xs",
    "xt",
    "xu",
    "xv",
    "xw",
    "xx",
    "xy",
    "xz",
    "y",
    "ya",
    "yb",
    "yc",
    "yd",
    "ye",
    "yf",
    "yg",
    "yh",
    "yi",
    "yj",
    "yk",
    "yl",
    "ym",
    "yn",
    "yo",
    "yp",
    "yq",
    "yr",
    "ys",
    "yt",
    "yu",
    "yv",
    "yw",
    "yx",
    "yy",
    "yz",
    "z",
    "za",
    "zb",
    "zc",
    "zd",
    "ze",
    "zeus",
    "zf",
    "zg",
    "zh",
    "zi",
    "zj",
    "zk",
    "zl",
    "zm",
    "zn",
    "zo",
    "zp",
    "zq",
    "zr",
    "zs",
    "zt",
    "zu",
    "zv",
    "zw",
    "zx",
    "zy",
    "zz"
}

false_positive_ips = ""

false_positive_ips = is_wildcard_record_on(sys.argv[1])

# iterate through all subdomains above
for val in subs_set:
    full_domain = val + '.' + sys.argv[1]
    ip_address = ''
    try:
        ip_address = socket.gethostbyname(full_domain)
    except:
        pass
    # if domain has wildcard record and resolved IP is a false positive
    if false_positive_ips and ip_address in false_positive_ips:
        continue # skip to next subdomain
    elif len(ip_address)>0:
        print(full_domain)
