def __raw_recv(self, datagrama):
    dscp, ecn, identification, flags, frag_offset, ttl, proto, \
        src_addr, dst_addr, payload = read_ipv4_header(datagrama)
    if dst_addr == self.meu_endereco:
        # atua como host
        if proto == IPPROTO_TCP and self.callback:
            self.callback(src_addr, dst_addr, payload)
    else:
        # atua como roteador
        next_hop = self._next_hop(dst_addr)

        # Recuperando cabeçalho para decrementar TTL
        dscp, ecn, identification, flags, frag_offset, ttl, proto, src_addr, \
            dst_addr, payload = read_ipv4_header(datagrama)

        data = [read_ipv4_header(datagrama)]

        if ttl == 1:
            payload = struct.pack('!BBHI', 11, 0, 0, 0) + datagrama[:28]
            checksum = calc_checksum(payload)
            payload = struct.pack(
                '!BBHI', 11, 0, checksum, 0) + datagrama[:28]

            self.enviar(payload, src_addr, IPPROTO_ICMP)
            return  # Descartando datagrama
        else:
            ttl -= 1

        # Refazendo cabeçalho com ttl decrementado
        header = struct.pack('!BBHHHBBH', 0x45, dscp | ecn, 20+len(payload), identification,
                             (flags << 13) | frag_offset, ttl, proto, 0)
        end = str2addr(src_addr)
        dest = str2addr(dst_addr)
        header += end + dest

        # Corrigindo checksum
        checksum = calc_checksum(header)

        header = struct.pack('!BBHHHBBH', 0x45, dscp | ecn, 20+len(payload), identification,
                             (flags << 13) | frag_offset, ttl, proto, checksum)

        end = str2addr(src_addr)
        dest = str2addr(dst_addr)
        header += end + dest

        self.enlace.enviar(header + payload, next_hop)
