# funcrunner

This is a minimal copy job to copy over funcrunner CLI tool from https://github.com/natenjoy/netdevops, which itself was copied from a repo from a former employee.

funcrunner feeds (as of April 2026) the redis source of data used by netops dcim agent to load network devices into dcim. The hope is to entirely deprecated and have netops dcim agent instead feed from the updated python version of network device discovery.

One reason to update this repo is for thigns like new data center buildouts. It is suspected that there are notions of region support hard baked into the code.
