# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

# construct the VSI
resource "ibm_is_instance" "txqueue_vsi" {
  name    = format("%s-txqueue-vsi", var.PREFIX)
  image   = local.hyper_protect_image.id
  profile = var.PROFILE
  keys    = [ibm_is_ssh_key.dap_sshkey.id]
  vpc     = ibm_is_vpc.dap_vpc.id
  tags    = local.tags
  zone    = "${var.REGION}-${var.ZONE}"

  # the user data field carries the encrypted contract, so all information visible at the hypervisor layer is encrypted
  user_data = file("./txqueue.yml")

  primary_network_interface {
    name            = "eth0"
    subnet          = ibm_is_subnet.dap_subnet.id
    security_groups = [ibm_is_security_group.dap_security_group.id]
  }

}

# attach a floating IP since we would like to access the embedded server via the internet
resource "ibm_is_floating_ip" "txqueue_floating_ip" {
  name   = format("%s-txqueue-floating-ip", var.PREFIX)
  target = ibm_is_instance.txqueue_vsi.primary_network_interface[0].id
  tags   = local.tags
}

resource "ibm_dns_record" "txqueue_dns_record" {
  data               = ibm_is_floating_ip.txqueue_floating_ip.address
  domain_id          = data.ibm_dns_domain.dns_domain.id
  host               = "${var.PREFIX}-txqueue"
  responsible_person = replace(var.CONTACT, "@", ".")
  ttl                = var.DNS_RECORD_TTL
  type               = "a"
}

# log the floating IP for convenience
output "txqueue_ip" {
  value = resource.ibm_is_floating_ip.txqueue_floating_ip.address
  description = "The public IP address of the VSI" 
}