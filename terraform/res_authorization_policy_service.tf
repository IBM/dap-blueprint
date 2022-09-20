# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

# construct the VSI
resource "ibm_is_instance" "authorization_policy_service_vsi" {
  name    = format("%s-ap-vsi", var.PREFIX)
  image   = local.hyper_protect_image.id
  profile = var.PROFILE
  keys    = [ibm_is_ssh_key.dap_sshkey.id]
  vpc     = ibm_is_vpc.dap_vpc.id
  tags    = local.tags
  zone    = "${var.REGION}-${var.ZONE}"

  # the user data field carries the encrypted contract, so all information visible at the hypervisor layer is encrypted
  user_data = file("./authorization_policy_service_contract_encrypted.yml")

  primary_network_interface {
    name            = "eth0"
    subnet          = ibm_is_subnet.dap_subnet.id
    security_groups = [ibm_is_security_group.dap_security_group.id]
  }

}

# attach a floating IP since we would like to access the embedded server via the internet
resource "ibm_is_floating_ip" "authorization_policy_service_floating_ip" {
  name   = format("%s-ap-floating-ip", var.PREFIX)
  target = ibm_is_instance.authorization_policy_service_vsi.primary_network_interface[0].id
  tags   = local.tags
}

# log the floating IP for convenience
output "authorization_policy_service_ip" {
  value = resource.ibm_is_floating_ip.authorization_policy_service_floating_ip.address
  description = "The public IP address of the VSI" 
}