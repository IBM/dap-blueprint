# Design Memo

## Initial wallet creation sequence

wallet:create_new_wallet()
    seed = mnemonic.make_seed()
    k = keystore.from_seed(seed,..)
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase)
        der = "m/"
        xtype = 'standard'
        keystore.add_xprv_from_seed(bip32_seed, xtype, der)
            rootnode = BIP32Node.from_rootseed(bip32_seed, xtype=xtype)
                I = hmac_oneshot(b"Bitcoin seed", seed, hashlib.sha512)
                master_k = I[0:32]
                master_c = I[32:]
                return BIP32Node(xtype=xtype, eckey=ecc.ECPrivkey(master_k), chaincode=master_c)
            node = rootnode.subkey_at_private_derivation(derivation)
                parent_pubkey = ecc.ECPrivkey(parent_privkey).get_public_key_bytes(compressed=True)
                fingerprint = hash_160(parent_pubkey)[0:4]
                child_number = child_index.to_bytes(length=4, byteorder="big")
                print('bip32:subkey_at_private_derivation: xtype={} depth={} child_number={}'.format(self.xtype, depth, child_number))
                return BIP32Node(xtype=self.xtype, eckey=ecc.ECPrivkey(privkey), chaincode=chaincode, depth=depth, fingerprint=fingerprint, child_number=child_number)
            self.add_xprv(node.to_xprv())
                payload = self.to_xprv_bytes(net=net)
                    payload = (xprv_header(self.xtype, net=net) +
                    bytes([self.depth]) +
                    self.fingerprint +
                    self.child_number +
                    self.chaincode +
                    bytes([0]) +
                    self.eckey.get_secret_bytes())
                    return payload
                return EncodeBase58Check(payload)
                self.xprv = xprv
                self.add_xpub(bip32.xpub_from_xprv(xprv))
                    return BIP32Node.from_xkey(xprv).to_xpub()
                        xkey = DecodeBase58Check(xkey)
                        depth = xkey[4]
                        fingerprint = xkey[5:9]
                        child_number = xkey[9:13]
                        chaincode = xkey[13:13 + 32]
                        header = int.from_bytes(xkey[0:4], byteorder='big')
                        if header in net.XPRV_HEADERS_INV:
                            headers_inv = net.XPRV_HEADERS_INV
                            is_private = True
                        elif header in net.XPUB_HEADERS_INV:
                            headers_inv = net.XPUB_HEADERS_INV
                            is_private = False
                        else:
                            raise InvalidMasterKeyVersionBytes(f'Invalid extended key format: {hex(header)}')
                        xtype = headers_inv[header]
                        if is_private:
                            eckey = ecc.ECPrivkey(xkey[13 + 33:])
                        else:
                            eckey = ecc.ECPubkey(xkey[13 + 32:])
                        return BIP32Node(xtype=xtype, eckey=eckey, chaincode=chaincode, depth=depth, fingerprint=fingerprint, child_number=child_number)
                    payload = self.to_xpub_bytes(net=net)
                        payload = (xpub_header(self.xtype, net=net) +
                            bytes([self.depth]) +
                            self.fingerprint +
                            self.child_number +
                            self.chaincode +
                            self.eckey.get_public_key_bytes(compressed=True))
                        return payload
                    return EncodeBase58Check(payload)
                self.xpub = xpub
                root_fingerprint, derivation_prefix = bip32.root_fp_and_der_prefix_from_xkey(xpub)
                    node = BIP32Node.from_xkey(xkey)
                    derivation_prefix = None
                    root_fingerprint = None
                    if node.depth == 0:
                        derivation_prefix = 'm'
                        root_fingerprint = node.calc_fingerprint_of_this_node().hex().lower()
                    elif node.depth == 1:
                        child_number_int = int.from_bytes(node.child_number, 'big')
                        derivation_prefix = convert_bip32_intpath_to_strpath([child_number_int])
                        root_fingerprint = node.fingerprint.hex()
                    return root_fingerprint, derivation_prefix
                self.add_key_origin(derivation_prefix=derivation_prefix, root_fingerprint=root_fingerprint)
                    self._root_fingerprint = root_fingerprint
                    self._derivation_prefix = normalize_bip32_derivation(derivation_prefix)
            self.add_key_origin_from_root_node(derivation_prefix=derivation, root_node=rootnode)
                child_node1 = root_node.subkey_at_private_derivation(derivation_prefix)
                    if isinstance(path, str):
                        path = convert_bip32_path_to_list_of_uint32(path)
                    depth = self.depth
                    chaincode = self.chaincode
                    privkey = self.eckey.get_secret_bytes()
                    print('bip32:subkey_at_private_derivation: path={}'.format(path))
                    for child_index in path:
                        parent_privkey = privkey
                        privkey, chaincode = CKD_priv(privkey, chaincode, child_index)
                        depth += 1
                    parent_pubkey = ecc.ECPrivkey(parent_privkey).get_public_key_bytes(compressed=True)
                    fingerprint = hash_160(parent_pubkey)[0:4]
                    child_number = child_index.to_bytes(length=4, byteorder="big")
                    print('bip32:subkey_at_private_derivation: xtype={} depth={} child_number={}'.format(self.xtype, depth, child_number))
                    return BIP32Node(xtype=self.xtype,
                         eckey=ecc.ECPrivkey(privkey),
                         chaincode=chaincode,
                         depth=depth,
                         fingerprint=fingerprint,
                         child_number=child_number)
                child_pubkey_bytes1 = child_node1.eckey.get_public_key_bytes(compressed=True)
                child_node2 = BIP32Node.from_xkey(self.xpub)
                child_pubkey_bytes2 = child_node2.eckey.get_public_key_bytes(compressed=True)
                if child_pubkey_bytes1 != child_pubkey_bytes2:
                    raise Exception("(xpub, derivation_prefix, root_node) inconsistency")
                self.add_key_origin(derivation_prefix=derivation_prefix, root_fingerprint=root_node.calc_fingerprint_of_this_node().hex().lower())
                    self._root_fingerprint = root_fingerprint
                    self._derivation_prefix = normalize_bip32_derivation(derivation_prefix)
    wallet.synchronize()
        with self.lock:
            self.synchronize_sequence(False)
                limit = self.gap_limit_for_change if for_change else self.gap_limit
                while True:
                    num_addr = self.db.num_change_addresses() if for_change else self.db.num_receiving_addresses()
                        return len(self.receiving_addresses)
                    if num_addr < limit:
                        self.create_new_address(for_change)
                            with self.lock:
                                n = self.db.num_change_addresses() if for_change else self.db.num_receiving_addresses()
                                address = self.derive_address(for_change, n)
                                    x = self.derive_pubkeys(for_change, n)
                                        return self.keystore.derive_pubkey(c, i)
                                        for_change = int(for_change)
                                        xpub = self.xpub_change if for_change else self.xpub_receive
                                        if xpub is None:
                                            rootnode = BIP32Node.from_xkey(self.xpub)
                                            xpub = rootnode.subkey_at_public_derivation((for_change,)).to_xpub()
                                                if isinstance(path, str):
                                                    path = convert_bip32_path_to_list_of_uint32(path)
                                                depth = self.depth
                                                chaincode = self.chaincode
                                                pubkey = self.eckey.get_public_key_bytes(compressed=True)
                                                print('bip32:subkey_at_public_derivation: path={} depth={}'.format(path, depth))
                                                for child_index in path: path=(0,)
                                                    parent_pubkey = pubkey
                                                    pubkey, chaincode = CKD_pub(pubkey, chaincode, child_index)
                                                    depth += 1
                                                fingerprint = hash_160(parent_pubkey)[0:4]
                                                child_number = child_index.to_bytes(length=4, byteorder="big")
                                                print('bip32:BIP32Node:subkey_at_public_derivation: xtype={} depth={} child_number={}'.format(self.xtype, depth, child_number))
                                                return BIP32Node(xtype=self.xtype, eckey=ecc.ECPubkey(pubkey), chaincode=chaincode, depth=depth, fingerprint=fingerprint, child_number=child_number)

                                            if for_change:
                                                self.xpub_change = xpub
                                            else:
                                                self.xpub_receive = xpub
                                        return self.get_pubkey_from_xpub(xpub, (n,))
                                            node = BIP32Node.from_xkey(xpub).subkey_at_public_derivation(sequence)
                                                if isinstance(path, str):
                                                    path = convert_bip32_path_to_list_of_uint32(path)
                                                depth = self.depth
                                                chaincode = self.chaincode
                                                pubkey = self.eckey.get_public_key_bytes(compressed=True)
                                                print('bip32:subkey_at_public_derivation: path={} depth={}'.format(path, depth))
                                                for child_index in path: path=(0,)
                                                    parent_pubkey = pubkey
                                                    pubkey, chaincode = CKD_pub(pubkey, chaincode, child_index)
                                                    depth += 1
                                                fingerprint = hash_160(parent_pubkey)[0:4]
                                                child_number = child_index.to_bytes(length=4, byteorder="big")
                                                print('bip32:BIP32Node:subkey_at_public_derivation: xtype={} depth={} child_number={}'.format(self.xtype, depth, child_number))
                                                return BIP32Node(xtype=self.xtype, eckey=ecc.ECPubkey(pubkey), chaincode=chaincode, depth=depth, fingerprint=fingerprint, child_number=child_number)

                                            print('keystore:Xpub:get_pubkey_from_xpub: xpub={} sequence={} node={}'.format(xpub, sequence, node))
                                            return node.eckey.get_public_key_hex(compressed=True)


                                    adr = self.pubkeys_to_address(x)
                                    return adr
                                self.db.add_change_address(address) if for_change else self.db.add_receiving_address(address)
                                self.add_address(address)
                                if for_change:
                                    # note: if it's actually used, it will get filtered later
                                    self._unused_change_addresses.append(address)
                               return address
                        continue
                    if for_change:
                        last_few_addresses = self.get_change_addresses(slice_start=-limit)
                    else:
                        last_few_addresses = self.get_receiving_addresses(slice_start=-limit)
                    if any(map(self.address_is_old, last_few_addresses)):
                        self.create_new_address(for_change)
                    else:
                        break
            self.synchronize_sequence(True)


depth=0 index=0, 1, 2 3, 4, ..., 19
child index 0000, 0000, 0001, 0002, ..., 000\x13
depth          0,    1,    1,    1, ,,,,   1
change
child index 0001, 0000, 0001, 0002, 0003, 0004, 0005
depth          0,    1,    1,    1,    1,    1,    1


