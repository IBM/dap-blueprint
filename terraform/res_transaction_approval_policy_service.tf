# construct the VSI
resource "ibm_is_instance" "transaction_approval_policy_service_vsi" {
  name    = format("%s-tap-vsi", var.PREFIX)
  image   = local.hyper_protect_image.id
  profile = var.PROFILE
  keys    = [ibm_is_ssh_key.dap_sshkey.id]
  vpc     = ibm_is_vpc.dap_vpc.id
  tags    = local.tags
  zone    = "${var.REGION}-${var.ZONE}"

  # the user data field carries the encrypted contract, so all information visible at the hypervisor layer is encrypted
  user_data = hpcr_contract_encrypted.transaction_approval_policy_service_contract.rendered

  primary_network_interface {
    name            = "eth0"
    subnet          = ibm_is_subnet.dap_subnet.id
    security_groups = [ibm_is_security_group.dap_security_group.id]
  }

}

# attach a floating IP since we would like to access the embedded server via the internet
resource "ibm_is_floating_ip" "transaction_approval_policy_service_floating_ip" {
  name   = format("%s-tap-floating-ip", var.PREFIX)
  target = ibm_is_instance.transaction_approval_policy_service_vsi.primary_network_interface[0].id
  tags   = local.tags
}

# log the floating IP for convenience
output "transaction_approval_policy_service_ip" {
  value = resource.ibm_is_floating_ip.transaction_approval_policy_service_floating_ip.address
  description = "The public IP address of the VSI" 
}