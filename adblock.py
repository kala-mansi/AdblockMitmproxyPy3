"""
An mitmproxy adblock script!
(Required python modules: re2 and adblockparser)

(c) 2015 epitron
"""

import re
from mitmproxy.script import concurrent
from adblockparser import AdblockRules
from glob import glob


def combined(filenames):
    '''
    Open and combine many files into a single generator which returns all
    of their lines. (Like running "cat" on a bunch of files.)
    '''
    for filename in filenames:
        with open(filename) as file:
            for line in file:
                yield line


def load_rules(blocklists=None):
    rules = AdblockRules(
        combined(blocklists),
        use_re2=False,
        max_mem=512 * 1024 * 1024
        # supported_options=['script', 'domain', 'image', 'stylesheet', 'object']
    )

    return rules


blocklists = glob("easylists/*")

if len(blocklists) == 0:
    raise SystemExit
else:
    for list in blocklists:
        print("  |_ %s" % list)

rules = load_rules(blocklists)
print("")
print("* Done! Proxy server is ready to go!")

IMAGE_MATCHER = re.compile(r"\.(png|jpe?g|gif)$")
SCRIPT_MATCHER = re.compile(r"\.(js)$")
STYLESHEET_MATCHER = re.compile(r"\.(css)$")


@concurrent
def request(flow):
    req = flow.request
    # print(req.url)
    # accept = flow.request.headers["Accept"]
    # print("accept: %s" % flow.request.accept)

    options = {'domain': req.host}

    if IMAGE_MATCHER.search(req.path):
        options["image"] = True
    elif SCRIPT_MATCHER.search(req.path):
        options["script"] = True
    elif STYLESHEET_MATCHER.search(req.path):
        options["stylesheet"] = True

    if rules.should_block(req.url, options):
        print("vvvvvvvvvvvvvvvvvvvv BLOCKED vvvvvvvvvvvvvvvvvvvvvvvvvvv")
        print("blocked-url: %s" % flow.request.url)
        print("|\n" * 10)
        flow.kill()
    else:
        pass
        # print("url: %s" % flow.request.url)
