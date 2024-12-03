from portscan_v import PortScan

def main(target, port_count):
    target = target
    port_count = int(port_count)
    scan = PortScan(target, port_count)
    scan.port_rotate()

    banners = scan.banners_port
    o_port = scan.open_port

    if len(banners) == 0 and len(o_port) == 0:
        print('No open ports found')
        return
    else:
        if target.startswith("http"):
            target_print = target.split("/")[2]
            print(f'\n\nDomain(IP) Summary: {target_print}\n{"*"*50}')
        else:
            print(f'\n\nDomain(IP) Summary: {target}\n{"*"*50}')
        for bann in banners:
            print(f' Port: {bann:5} Banner: {banners[bann]}')
        for o in o_port:
            print(f' Port: {o:5} Service: {o_port[o]}')

if __name__ == "__main__":
    target = input('\n[*] Input Domain or ip addres for the scan >>>')
    main(target, 65535)