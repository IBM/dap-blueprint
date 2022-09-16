# Digital Asset Platform Blueprint

**A patent disclosure is under review. Please do not share the content of this repo with external customers without NDA.**

This repo maintains the document and code to define Digital Asset Platform Blueprint (dap-blueprint).

This blueprint demonstrates how Hyper Protect services can be configured to provide a secure digital asset
signing service with technical assurance where even administrators cannot compromise the system.

This blueprint comes with a CLI script program, which includes a frontend wallet for testing purposes (e.g.
a modified Electrum for Bitcoin). A consumer of this blueprint is expected to replace the frontend with
a full-blown wallet implementation.

The current API design can be found [here](API.md).

Also refer to [the transaction sequences](Transaction-Sequences.md) and [the threat model](Threat-Model.md) to understand the current design.

Please note that this is a working draft being updated constantly.

For the very initial MVP prototype, check [the mvp1 branch](https://github.ibm.com/ZaaS/dap-blueprint/blob/mvp1/demo/HOWTO.md)

<p align="center">
  <img src="./images/dap-blueprint-overview.png">
</p>
