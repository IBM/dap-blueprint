# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

# make sure to target the correct region and zone
provider "ibm" {
  region = var.REGION
  zone   = "${var.REGION}-${var.ZONE}"
}

locals {
  # some reusable tags that identify the resources created by his sample
  tags = ["hpcr", "dap", var.PREFIX]
}

# the VPC
resource "ibm_is_vpc" "dap_vpc" {
  name = format("%s-vpc", var.PREFIX)
  tags = local.tags
}

# the security group
resource "ibm_is_security_group" "dap_security_group" {
  name = format("%s-security-group", var.PREFIX)
  vpc  = ibm_is_vpc.dap_vpc.id
  tags = local.tags
}

# rule that allows the VSI to make outbound connections, this is required
# to connect to the logDNA instance as well as to docker to pull the image
resource "ibm_is_security_group_rule" "dap_outbound" {
  group     = ibm_is_security_group.dap_security_group.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

# rule that allows inbound traffic to the nginx server
resource "ibm_is_security_group_rule" "dap_inbound" {
  group     = ibm_is_security_group.dap_security_group.id
  direction = "inbound"
  remote    = "0.0.0.0/0"
  tcp {
    port_min = 4000
    port_max = 10000
  }
}

# the subnet
resource "ibm_is_subnet" "dap_subnet" {
  name                     = format("%s-subnet", var.PREFIX)
  vpc                      = ibm_is_vpc.dap_vpc.id
  total_ipv4_address_count = 256
  zone                     = "${var.REGION}-${var.ZONE}"
  tags                     = local.tags
}

# create a random key pair, because for formal reasons we need to pass an SSH key into the VSI. It will not be used, that's why
# it can be random
resource "tls_private_key" "dap_rsa_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# we only need this because VPC expects this
resource "ibm_is_ssh_key" "dap_sshkey" {
  name       = format("%s-key", var.PREFIX)
  public_key = tls_private_key.dap_rsa_key.public_key_openssh
  tags       = local.tags
}

# locate the latest hyper protect image
data "ibm_is_images" "hyper_protect_images" {
  visibility = "public"
  status     = "available"
}

locals {
  # filter the available images down to the hyper protect one
  hyper_protect_image = one(toset([for each in data.ibm_is_images.hyper_protect_images.images : each if each.os == "hyper-protect-1-0-s390x" && each.architecture == "s390x"]))
}
