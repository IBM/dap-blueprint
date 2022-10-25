# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

# archive of the folder containing docker-compose file. This folder could create additional resources such as files 
# to be mounted into containers, environment files etc. This is why all of these files get bundled in a tgz file (base64 encoded)
resource "hpcr_tgz" "fraud_detection_policy_service_workload" {
  folder = "fraud_detection_policy_service"
}

locals {
  fraud_detection_policy_service_compose = {
    "compose" : {
      "archive" : hpcr_tgz.fraud_detection_policy_service_workload.rendered
    }
  }
  fraud_detection_policy_service_workload = merge(local.workload_template, local.fraud_detection_policy_service_compose)
  # contract in clear text
  fraud_detection_policy_service_contract = yamlencode({
    "env" : local.env,
    "workload" : local.fraud_detection_policy_service_workload
  })
}

# In this step we encrypt the fields of the contract and sign the env and workload field. The certificate to execute the 
# encryption it built into the provider and matches the latest HPCR image. If required it can be overridden. 
# We use a temporary, random keypair to execute the signature. This could also be overriden. 
resource "hpcr_contract_encrypted" "fraud_detection_policy_service_contract" {
  contract = local.fraud_detection_policy_service_contract
}

resource "local_file" "fraud_detection_policy_service_contract" {
  content  = local.fraud_detection_policy_service_contract
  filename = "fdp_plain.yml"
}

resource "local_file" "fraud_detection_policy_service_contract_encrypted" {
  content  = hpcr_contract_encrypted.fraud_detection_policy_service_contract.rendered
  filename = "fdp.yml"
}
