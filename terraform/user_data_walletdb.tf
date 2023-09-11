# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

# archive of the folder containing docker-compose file. This folder could create additional resources such as files
# to be mounted into containers, environment files etc. This is why all of these files get bundled in a tgz file (base64 encoded)
resource "hpcr_tgz" "walletdb_workload" {
  folder = "walletdb"
}

locals {
  walletdb_compose = {
    "compose" : {
      "archive" : hpcr_tgz.walletdb_workload.rendered
    }
  }
  walletdb_workload = merge(local.workload_template, local.walletdb_compose)
  # contract in clear text
  walletdb_contract = yamlencode({
    "env" : local.env,
    "workload" : local.walletdb_workload
  })
  walletdb_contract_plain = yamlencode({
    "env" : yamlencode(local.env),
    "workload" : yamlencode(local.walletdb_workload)
  })
}

# In this step we encrypt the fields of the contract and sign the env and workload field. The certificate to execute the
# encryption it built into the provider and matches the latest HPCR image. If required it can be overridden.
# We use a temporary, random keypair to execute the signature. This could also be overriden.
resource "hpcr_contract_encrypted" "walletdb_contract" {
  contract = local.walletdb_contract
  #cert = file(var.HPCR_CERT)
}

resource "local_file" "walletdb_contract" {
  content  = local.walletdb_contract_plain
  filename = "walletdb_plain.yml"
}

resource "local_file" "walletdb_contract_encrypted" {
  content  = hpcr_contract_encrypted.walletdb_contract.rendered
  filename = "walletdb.yml"
}