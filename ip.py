from iputils import *
import struct
import ipaddress


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.id = 0

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

            if (ttl - 1) == 0:
                checksum = calc_checksum(struct.pack(
                    '!BBHI', 11, 0, 0, 0) + datagrama[:28])
                self.enviar(struct.pack(
                    '!BBHI', 11, 0, checksum, 0) + datagrama[:28], src_addr, IPPROTO_ICMP)
                return
            else:
                ttl -= 1

            header = struct.pack('!BBHHHBBH', 0x45, dscp | ecn, 20+len(payload), identification,
                                 (flags << 13) | frag_offset, ttl, proto, 0)
            end = str2addr(src_addr)
            dest = str2addr(dst_addr)
            header += end + dest

            checksum = calc_checksum(header)

            header = struct.pack('!BBHHHBBH', 0x45, dscp | ecn, 20+len(payload), identification,
                                 (flags << 13) | frag_offset, ttl, proto, checksum)

            end = str2addr(src_addr)
            dest = str2addr(dst_addr)
            header += end + dest

            self.enlace.enviar(header + payload, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        matchs = []
        for cidr, next_hop in self.tabela:
            if ipaddress.ip_address(dest_addr) in ipaddress.ip_network(cidr):
                matchs.append((cidr, next_hop))

        aux = 0
        next_hop_final = None
        for cidr, next_hop in matchs:
            _, n = cidr.split("/", 1)
            if int(n) >= int(aux):
                aux = n
                next_hop_final = next_hop

        return next_hop_final

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, protocol=IPPROTO_TCP):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        header = struct.pack('!BBHHHBBH', ((4 << 4) | 5), 0, (20 + len(segmento)), self.id,
                             0, 64, protocol, 0)
        end = str2addr(self.meu_endereco)
        dest = str2addr(dest_addr)

        header += end + dest

        header = struct.pack('!BBHHHBBH', ((4 << 4) | 5), 0, (20 + len(segmento)), self.id, 0, 64,
                             protocol, calc_checksum(header))
        end = str2addr(self.meu_endereco)
        dest = str2addr(dest_addr)

        header += end + dest
        self.id += 1
        self.enlace.enviar(header + segmento, next_hop)
