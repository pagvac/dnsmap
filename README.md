# dnsmap, a simple subdomain bruteforcer

This is the project page of the new version of dnsmap which has been ported from C to python by its original author. The [old version](https://github.com/resurrecting-open-source-projects/dnsmap) should no longer be used.

See an example command below. Yup, it's that simple! 😜

dnsmap intentionally ships without command-line flags. The goal is to keep the tool approachable for OSINT newcomers who just need a single command that works out of the box—no option hunting, no prerequisite tuning.

Run it against any domain:

```
$ python3 dnsmap.py github.com
dnsmap 0.40 - DNS Network Mapper by github.com/pagvac
> Querying scraping sources (done)                                                                                                                             
> Performing DNS bruteforcing using internal list (done • 581.3/s)   
ns2.github.com
slack.github.com
forms.github.com
unity.github.com
github.github.com
services.github.com
docs.github.com
pages.github.com
brand.github.com
desktop.github.com
learn.github.com
central.github.com
emails.github.com
cs.github.com
info.github.com
og.github.com
lfs.github.com
windows.github.com
skyline.github.com
partner.github.com
garage.github.com
action.github.com
brasil.github.com
galaxy.github.com
government.github.com
status.github.com
developer.github.com
campus.github.com
resources.github.com
next.github.com
community.github.com
uploads.github.com
universe.github.com
guides.github.com
shop.github.com
enterprise.github.com
insights.github.com
atom-installer.github.com
gist.github.com
graphql.github.com
codeql.github.com
securitylab.github.com
maintainers.github.com
cli.github.com
[stats] duration=198.43s attempted=100735 found=44 scrape_found=10 avg_per_sec=507.67
```

The progress bar, tuning messages, and scrape telemetry all stay on stderr. Only the confirmed subdomains land on stdout, so redirecting the output gives a clean list ready for whatever tooling you use next:

```
$ python3 dnsmap.py example.com > subs.txt
```

Because the file only receives enumerated subdomains, you can feed it directly into resolvers, HTTP fuzzers, or additional OSINT pipelines without extra filtering.
