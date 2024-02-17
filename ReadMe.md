# SigmaDouble6
---

## Usage:

<details>
<summary>from source (.py)</summary>

```sh
usage: sigmadouble.py [-h] [-v] [-f filename] [-i mapped_ipv4]
                      [-p mapped_port_base]
                      [-s mapping_stored_filename | -l mapping_loaded_filename]

CLI argument parsing

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbosity
  -f filename, --filename filename
                        filename of UCC log
  -i mapped_ipv4, --ip mapped_ipv4
                        mapped IPv4 address; only for mapping stored filename
  -p mapped_port_base, --port mapped_port_base
                        mapped TCP listening port base; only for mapping
                        stored filename
  -s mapping_stored_filename, --store mapping_stored_filename
                        mapping stored filename, from UCC log; YAML formatted
  -l mapping_loaded_filename, --load mapping_loaded_filename
                        mapping loaded filename, to UCC log; YAML formatted
```
</details>

<details>
<summary>from binary (.exe)</summary>

```sh
usage: sigmadouble.exe [-h] [-v] [-f filename] [-i mapped_ipv4] [-p mapped_port_base]
                       [-s mapping_stored_filename | -l mapping_loaded_filename]

CLI argument parsing

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbosity
  -f filename, --filename filename
                        filename of UCC log
  -i mapped_ipv4, --ip mapped_ipv4
                        mapped IPv4 address; only for mapping stored filename
  -p mapped_port_base, --port mapped_port_base
                        mapped TCP listening port base; only for mapping stored filename
  -s mapping_stored_filename, --store mapping_stored_filename
                        mapping stored filename, from UCC log; YAML formatted
  -l mapping_loaded_filename, --load mapping_loaded_filename
                        mapping loaded filename, to UCC log; YAML formatted
```
</details>

## Description:
A test double to **emulate** Sigma handshaking based on existing log.
This design is for the condition that Sigma instances such as DUT and/or sniffer are unavailable.

A Sigma instance follows the **WTS CAPI specification** to receive and send formatted strings over a TCP socket; UCC core sends CAPI request to a Sigma instance, and the Sigma instance sends CAPI response to UCC core accordingly.

This test double is designed to replace Sigma instances by a few socket servers; the socket client, i.e. UCC core, switches its connection with those socket servers (instead of actual Sigma instances). All the CAPI request/response patterns are retrieved from existing UCC log.
This test double would:
> parse the specified UCC log,
> gather every Sigma instances,
> gather request/response from each Sigma instances, and
> spawn TCP socket servers with request/response collection accordingly.

The UCC core must alter:
> initialization configuration, i.e. AllInitConfig_\*.txt file in cmds/WTS-\* directory, with the IP and port setting from this test double.
> > Notice here, when DUT is one of testbeds, the handle (IP-port pair) of the testbed is recommended to be commented/removed.

Thus, when UCC core sends request to test double, then, test double will send corresponding response back; **just like replaying the tapes of music**.

## Build:

<details>
<summary>Cross-platform packaging using <b>Wine</b></summary>

Building _Windows 11_ binary executable steps under _Ubuntu 20.04_ are following.

* To build the docker image using existing Dockerfile; **Wine** installation is included in the Dockerfile
```sh
docker build -f ubuntu-20-04-wine.dockerfile -t wine-20-04 . --build-arg UID=$UID --build-arg USER=$USER --build-arg PASSWORD="demonslayer"
```
* To disable the access control of X-server
```sh
xhost +
```

* To launch the docker container; current working directory is mounted to _/mnt_
```sh
docker run -it --name wine-20-04-inst --device /dev/snd --device=/dev/dri -e DISPLAY=$DISPLAY -e XMODIFIERS=@im=fcitx -e QT_IM_MODULE=fcitx -e GTK_IM_MODULE=fcitx -v /tmp/.X11-unix:/tmp/.X11-unix:ro -v $(pwd):/mnt --net=host wine-20-04 bash
```

* To download a suitable python installer such as v3.8 under the container
```sh
wget https://www.python.org/ftp/python/3.8.10/python-3.8.10-amd64.exe -O /mnt/python-3.8.10-amd64.exe
```

* To install the python installer under the container
```sh
WINEPREFIX=~/.wine64 wine /mnt/python-3.8.10-amd64.exe
```

* To install dependency for this _test double_ under the container
```sh
WINEPREFIX=~/.wine64 wine ~/.wine64/drive_c/users/`id -u -n`/AppData/Local/Programs/Python/Python38/python.exe -m pip install pyyaml
```

* To install dependency for packaging under the container
```sh
WINEPREFIX=~/.wine64 wine ~/.wine64/drive_c/users/`id -u -n`/AppData/Local/Programs/Python/Python38/python.exe -m pip install pyinstaller
```

* To package the binary executable under the container; the binary executable is stored in the distributable directory (i.e. _/mnt_)
```sh
WINEPREFIX=~/.wine64 wine ~/.wine64/drive_c/users/`id -u -n`/AppData/Local/Programs/Python/Python38/Scripts/pyinstaller.exe --clean --console --onefile /mnt/sigmadouble.py --distpath /mnt
```

* To exit the container
```sh
exit
```

* To enable the access control of X-server
```sh
xhost -
```

</details>

