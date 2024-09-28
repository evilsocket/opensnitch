<p align="center">
  <small>Join the project community on our server!</small>
  <br/><br/>
  <a href="https://discord.gg/btZpkp45gQ" target="_blank" title="Join our community!">
    <img src="https://dcbadge.limes.pink/api/server/https://discord.gg/btZpkp45gQ"/>
  </a>
</p>
<hr/>

<p align="center">
  <img alt="opensnitch" src="https://raw.githubusercontent.com/evilsocket/opensnitch/master/ui/opensnitch/res/icon.png" height="160" />
  <p align="center">
    <img src="https://github.com/evilsocket/opensnitch/workflows/Build%20status/badge.svg" />
    <a href="https://github.com/evilsocket/opensnitch/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/evilsocket/opensnitch.svg?style=flat-square"></a>
    <a href="https://github.com/evilsocket/opensnitch/blob/master/LICENSE.md"><img alt="Software License" src="https://img.shields.io/badge/license-GPL3-brightgreen.svg?style=flat-square"></a>
    <a href="https://goreportcard.com/report/github.com/evilsocket/opensnitch/daemon"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/evilsocket/opensnitch/daemon?style=flat-square"></a>
    <a href="https://repology.org/project/opensnitch/versions"><img src="https://repology.org/badge/tiny-repos/opensnitch.svg" alt="Packaging status"></a>
  </p>
</p>

<p align="center"><strong>OpenSnitch</strong> is a GNU/Linux application firewall.</p>

<p align="center">•• <a href="#key-features">Key Features</a> • <a href="#download">Download</a> • <a href="#installation">Installation</a> • <a href="#opensnitch-in-action">Usage examples</a> • <a href="#in-the-press">In the press</a> ••</p>

<p align="center">
  <img src="https://user-images.githubusercontent.com/2742953/85205382-6ba9cb00-b31b-11ea-8e9a-bd4b8b05a236.png" alt="OpenSnitch"/>
</p>

## Key features
 * Interactive outbound connections filtering.
 * [Block ads, trackers or malware domains](https://github.com/evilsocket/opensnitch/wiki/block-lists) system wide.
 * Ability to [configure system firewall](https://github.com/evilsocket/opensnitch/wiki/System-rules) from the GUI (nftables).
   - Configure input policy, allow inbound services, etc.
 * Manage [multiple nodes](https://github.com/evilsocket/opensnitch/wiki/Nodes) from a centralized GUI.
 * [SIEM integration](https://github.com/evilsocket/opensnitch/wiki/SIEM-integration)

## Download

Download deb/rpm packages for your system from https://github.com/evilsocket/opensnitch/releases

## Installation

#### deb
> $ sudo apt install ./opensnitch*.deb ./python3-opensnitch-ui*.deb

#### rpm
> $ sudo yum localinstall opensnitch-1*.rpm; sudo yum localinstall opensnitch-ui*.rpm 

Then run: `$ opensnitch-ui` or launch the GUI from the Applications menu.

Please, refer to [the documentation](https://github.com/evilsocket/opensnitch/wiki/Installation) for detailed information.

## OpenSnitch in action

Examples of OpenSnitch intercepting unexpected connections:

https://github.com/evilsocket/opensnitch/discussions/categories/show-and-tell

Have you seen a connection you didn't expect? [submit it!](https://github.com/evilsocket/opensnitch/discussions/new?category=show-and-tell)

## In the press

- 2017 [PenTest Magazine](https://twitter.com/pentestmag/status/857321886807605248)
- 11/2019 [It's Foss](https://itsfoss.com/opensnitch-firewall-linux/)
- 03/2020 [Linux Format #232](https://www.linux-magazine.com/Issues/2020/232/Firewalld-and-OpenSnitch)
- 08/2020 [Linux Magazine Polska #194](https://linux-magazine.pl/archiwum/wydanie/387)
- 08/2021 [Linux Format #280](https://github.com/evilsocket/opensnitch/discussions/631)
- 02/2022 [Linux User](https://www.linux-community.de/magazine/linuxuser/2022/03/)
- 06/2022 [Linux Magazine #259](https://www.linux-magazine.com/Issues/2022/259/OpenSnitch)

## Donations

If you find OpenSnitch useful and want to donate to the dedicated developers, you can do it from the **Sponsor this project** section on the right side of this repository.

You can see here who are the current maintainers of OpenSnitch:
https://github.com/evilsocket/opensnitch/commits/master

## Contributors

[See the list](https://github.com/evilsocket/opensnitch/graphs/contributors)

## Translating

<a href="https://hosted.weblate.org/engage/opensnitch/">
<img src="https://hosted.weblate.org/widgets/opensnitch/-/glossary/multi-auto.svg" alt="Translation status" />
</a>
