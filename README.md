# opsi-deploy-client-agent

This repository contains a script which is intended to be run on an opsi conf-server.
If it is placed inside an opsi-client-agent, opsi-linux-client-agent or opsi-mac-client-agent, it copies the relevant files to the desired client and sets it up to run the components of an opsi-client-agent.

## usage

```
./opsi-deploy-client-agent <client_fqdn>
```