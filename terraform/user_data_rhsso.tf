# archive of the folder containing docker-compose file. This folder could create additional resources such as files 
# to be mounted into containers, environment files etc. This is why all of these files get bundled in a tgz file (base64 encoded)
resource "hpcr_tgz" "rhsso_workload" {
  folder = "rhsso"
}

locals {
  rhsso_compose = {
    "compose" : {
      "archive" : hpcr_tgz.rhsso_workload.rendered
    }
  }
  rhsso_workload = merge(local.workload_template, local.rhsso_compose)
  # contract in clear text
  rhsso_contract = yamlencode({
    "env" : local.env,
    "workload" : local.rhsso_workload
  })
}

# In this step we encrypt the fields of the contract and sign the env and workload field. The certificate to execute the 
# encryption it built into the provider and matches the latest HPCR image. If required it can be overridden. 
# We use a temporary, random keypair to execute the signature. This could also be overriden. 
resource "hpcr_contract_encrypted" "rhsso_contract" {
  contract = local.rhsso_contract
}

resource "local_file" "rhsso_contract" {
  content  = local.rhsso_contract
  filename = "rhsso_contract.yml"
}
