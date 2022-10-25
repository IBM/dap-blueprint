resource "ibm_is_subnet_reserved_ip" "transaction_proposer_reserved_ip" {
  subnet    = ibm_is_subnet.dap_subnet.id
  name      = format("%s-tp-reserved-ip", var.PREFIX)
  address   = "${replace(ibm_is_subnet.dap_subnet.ipv4_cidr_block, "0/24", 23)}"
}

# construct the VSI
resource "ibm_is_instance" "transaction_proposer_vsi" {
  name    = format("%s-tp-vsi", var.PREFIX)
  image   = local.hyper_protect_image.id
  profile = var.PROFILE
  keys    = [ibm_is_ssh_key.dap_sshkey.id]
  vpc     = ibm_is_vpc.dap_vpc.id
  tags    = local.tags
  zone    = "${var.REGION}-${var.ZONE}"

  # the user data field carries the encrypted contract, so all information visible at the hypervisor layer is encrypted
  user_data = file("./tp.yml")

  primary_network_interface {
    name            = "eth0"
    subnet          = ibm_is_subnet.dap_subnet.id
    security_groups = [ibm_is_security_group.dap_security_group.id]
    primary_ip {
      reserved_ip = ibm_is_subnet_reserved_ip.transaction_proposer_reserved_ip.reserved_ip
    }
  }
}

# attach a floating IP since we would like to access the embedded server via the internet
resource "ibm_is_floating_ip" "transaction_proposer_floating_ip" {
  name   = format("%s-tp-floating-ip", var.PREFIX)
  target = ibm_is_instance.transaction_proposer_vsi.primary_network_interface[0].id
  tags   = local.tags
}

output "rhsso_reserved_ip" {
  value = ibm_is_subnet_reserved_ip.transaction_proposer_reserved_ip.address
  description = "The reserved IP address of the VSI"
}

# log the floating IP for convenience
output "transaction_proposer_ip" {
  value = resource.ibm_is_floating_ip.transaction_proposer_floating_ip.address
  description = "The public IP address of the VSI" 
}