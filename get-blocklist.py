import shutil

from contextlib import closing
from ipaddress import ip_network, IPv4Address

import requests


def get_spamhaus_blocklist(urls):
    blocklist = []
    for url in urls:
        response = requests.get(url, params=None)
        response.raise_for_status()

        for address in response.text.splitlines():
            try:
                ipnetwork = ip_network(address.split(" ; ")[0])
                ipaddress = ipnetwork.network_address
                ipnetmask = ipnetwork.netmask
                ipnetmask_inversed = str(
                    IPv4Address(int(IPv4Address(ipnetmask)) ^ (2 ** 32 - 1))
                )
                blocklist.append(
                    f"access-list 110 deny ip {ipaddress} {ipnetmask_inversed} any\n"
                )
            except Exception as e:
                continue
    return blocklist


def get_dshield_blocklist(url):
    blocklist = []

    response = requests.get(url, params=None)
    response.raise_for_status()

    dshield_blocklist_list = response.text.splitlines()
    if dshield_blocklist_list:
        index_to_search = (
            dshield_blocklist_list.index(
                "Start	End	Netmask	Attacks	Name	Country	email"
            )
            + 1
        )

        for dshield_blocklist in dshield_blocklist_list[index_to_search:]:
            try:
                ipnetwork = ip_network(
                    f"{dshield_blocklist.split()[0]}/{dshield_blocklist.split()[2]}"
                )
                ipaddress = ipnetwork.network_address
                ipnetmask = ipnetwork.netmask
                ipnetmask_inversed = str(
                    IPv4Address(int(IPv4Address(ipnetmask)) ^ (2 ** 32 - 1))
                )
                blocklist.append(
                    f"access-list 110 deny ip {ipaddress} {ipnetmask_inversed} any\n"
                )
            except Exception as e:
                continue
        return blocklist


def add_blocklist_to_accesslist(
    block_list, primary_access_list, last_access_list_file
):
    add_at_begin = ["no access-list 110\n"]
    add_at_and = ["access-list 110 deny   ip any any\n", "end\n", "wr\n"]

    last_access_list = (
        add_at_begin + block_list + primary_access_list + add_at_and
    )

    with open(last_access_list_file, "w") as file:
        for rule in last_access_list:
            file.write(rule)


def get_accesslist_from_cisco_config(config_file):
    with open(config_file, "r") as file:
        config_file_strings = file.readlines()

    first_string_in_accesslist = [
        x for x in config_file_strings if "access-list 110 permit" in x
    ][0]
    index_start = config_file_strings.index(first_string_in_accesslist)
    index_end = (
        config_file_strings.index("access-list 110 deny   ip any any\n") + 1
    )

    accesslist = config_file_strings[index_start:index_end]
    clear_accesslist = [
        x for x in accesslist if not x.startswith("access-list 110 deny")
    ]

    return clear_accesslist


def main():
    blocklists = []

    spamhaus_urls = [
        "http://www.spamhaus.org/drop/drop.txt",
        "http://www.spamhaus.org/drop/edrop.txt",
    ]
    dshield_url = "https://www.dshield.org/block.txt"

    cisco_conf_file = r"/mnt/cifs/CFG_Dowload/HQRouter.cfg"
    last_access_list_file = "acl110last"
    dst_folder = r"/mnt/cifs/ACL-Upload"

    blocklists += get_spamhaus_blocklist(spamhaus_urls)
    # blocklists += get_dshield_blocklist(dshield_url)
    primary_access_list = get_accesslist_from_cisco_config(cisco_conf_file)

    add_blocklist_to_accesslist(
        blocklists, primary_access_list, last_access_list_file
    )

    shutil.copy2(last_access_list_file, dst_folder)


if __name__ == "__main__":
    main()
