This open source distribution contains documentation, scripts, and
other materials related to the BBR congestion control algorithm.

Quick links
---

* Linux TCP BBRv3 Release:
  * https://github.com/google/bbr/blob/v3/README.md
* BBR FAQ:
  * https://github.com/google/bbr/blob/master/Documentation/bbr-faq.md
* TCP BBR Quick-Start: Building and Running TCP BBR on Google Compute Engine:
  * https://github.com/google/bbr/blob/master/Documentation/bbr-quick-start.md
* Mailing list: Test results, performance evaluations, feedback, and BBR-related discussions are very welcome in the public e-mail list for BBR: https://groups.google.com/d/forum/bbr-dev

Latest BBR code from Google's BBR team
---

* For Linux TCP BBR:
  * https://github.com/google/bbr/blob/v3/net/ipv4/tcp_bbr.c

* For QUIC BBR:
  * https://github.com/google/quiche/blob/main/quiche/quic/core/congestion_control/bbr2_sender.cc
  * https://github.com/google/quiche/blob/main/quiche/quic/core/congestion_control/bbr2_sender.h

BBR v1 releases
---

* For Linux TCP BBR:
  * https://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git/tree/net/ipv4/tcp_bbr.c

* For QUIC BBR:
  * https://github.com/google/quiche/blob/main/quiche/quic/core/congestion_control/bbr_sender.cc
  * https://github.com/google/quiche/blob/main/quiche/quic/core/congestion_control/bbr_sender.h

BBR Internet Draft
---
* There is an Internet Draft specifying BBR:  
  * BBR is a Congestion Control Working Group (CCWG) "working group item"  
  * Target: publish an experimental RFC documenting the algorithm  
  * IETF working group members are collaborating on github  
    * [https://github.com/ietf-wg-ccwg/draft-ietf-ccwg-bbr](https://github.com/ietf-wg-ccwg/draft-ietf-ccwg-bbr)  
    * Ideas or suggestions? Feel free to file a github issue.  
    * Specific editorial suggestions? Feel free to propose a pull request.  
  * BBR Internet Draft:  draft-ietf-ccwg-bbr  
    * [https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/](https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/)  

Information About BBR
---
* There is a [blog post](https://cloudplatform.googleblog.com/2017/07/TCP-BBR-congestion-control-comes-to-GCP-your-Internet-just-got-faster.html) on the launch of BBR for Google.com, YouTube, and Google Cloud Platform  
* There is an [article describing BBR](http://cacm.acm.org/magazines/2017/2/212428-bbr-congestion-based-congestion-control/fulltext) in the February 2017 issue of CACM (the same content is in the [ACM Queue BBR article from Oct 2016](http://queue.acm.org/detail.cfm?id=3022184)).  
* \[[YouTube](https://www.youtube.com/watch?v=hIl_zXzU3DA)\] \[[slides](http://netdevconf.org/1.2/slides/oct5/04_Making_Linux_TCP_Fast_netdev_1.2_final.pdf)\] for a BBR talk at the Linux netdev 1.2 conference (Oct 2016\)  
* \[[YouTube](https://youtu.be/qjWTULVbiVc?t=3460)\] \[[slides](https://www.ietf.org/proceedings/97/slides/slides-97-iccrg-bbr-congestion-control-02.pdf)\] for a BBR talk in the ICCRG session at IETF 97 (Nov 2016\)  
* \[[YouTube](https://youtu.be/7wRXkQcD8PM?t=3317)\] \[[slides](https://www.ietf.org/proceedings/97/slides/slides-97-maprg-traffic-policing-in-the-internet-yuchung-cheng-and-neal-cardwell-00.pdf)\] for a talk covering policers and BBR's handling of policers, in the MAPRG session at IETF 97 (Nov 2016\)  
* \[[YouTube](https://youtu.be/_rf4EjkaRNo?t=5751)\] \[[slides](https://www.ietf.org/proceedings/98/slides/slides-98-iccrg-an-update-on-bbr-congestion-control-00.pdf)\] BBR talk at the ICCRG session at IETF 98 (Mar 2017\)  
* \[[YouTube](https://youtu.be/5EiUx_sXpak?t=1406)\] \[[slides](https://www.ietf.org/proceedings/99/slides/slides-99-iccrg-iccrg-presentation-2-00.pdf)\] BBR talk at the ICCRG session at IETF 99 (Jul 2017\)  
* \[[YouTube](https://www.youtube.com/watch?v=IGw5NVGBsDU&t=43m58s)\] \[[slides](https://datatracker.ietf.org/meeting/100/materials/slides-100-iccrg-a-quick-bbr-update-bbr-in-shallow-buffers/)\] BBR talk at the ICCRG session at IETF 100 (Nov 2017\)  
* \[[YouTube](https://www.youtube.com/watch?v=rHH9wFbms80&feature=youtu.be&t=52m09s)\] \[[slides](https://datatracker.ietf.org/meeting/101/materials/slides-101-iccrg-an-update-on-bbr-work-at-google-00)\] BBR talk at the ICCRG session at IETF 101 (Mar 2018\)  
* \[[YouTube](https://youtu.be/LdjavTiMrs0?t=1h10m3s)\] \[[slides](https://datatracker.ietf.org/meeting/102/materials/slides-102-iccrg-an-update-on-bbr-work-at-google-00)\] BBR Congestion Control Work at Google: IETF 102 Update  (Jul 2018\)  
* \[[YouTube](https://youtu.be/LdjavTiMrs0?t=1h36m42s)\] \[[slides](https://datatracker.ietf.org/meeting/102/materials/slides-102-iccrg-bbr-startup-behavior-01)\] BBR Congestion Control: IETF 102 Update: BBR Startup (Jul 2018\)  
* \[[YouTube](https://youtu.be/cJ-0Ti8ZlfE?t=210)\] \[[slides](https://datatracker.ietf.org/meeting/104/materials/slides-104-iccrg-an-update-on-bbr-00)\] BBR v2: A Model-based Congestion Control \- ICCRG at IETF 104 (Mar 2019\)  
* \[[YouTube](https://www.youtube.com/watch?v=6Njd4ApRsuo&feature=youtu.be&t=1149)\] \[[slides](https://datatracker.ietf.org/meeting/105/materials/slides-105-iccrg-bbr-v2-a-model-based-congestion-control-00)\] BBR v2: A Model-based Congestion Control: IETF 105 Update \- ICCRG (Jul 2019\)  
* \[[YouTube](https://www.youtube.com/watch?v=i3CpETXwA7Q&feature=youtu.be&t=1679)\] \[[slides](https://datatracker.ietf.org/meeting/106/materials/slides-106-iccrg-update-on-bbrv2)\] BBR v2: A Model-based Congestion Control: Performance Optimizations \- IETF 106 \- ICCRG (Nov 2019\)  
* \[[YouTube](https://www.youtube.com/watch?v=VIX45zMMZG8)\] BBR: A Model-based Congestion Control \- High-Speed Networking Workshop (May 2020\)  
* \[[YouTube](https://www.youtube.com/watch?v=tBuXblC0o1M&feature=youtu.be&t=3485)\] \[[slides](https://datatracker.ietf.org/meeting/109/materials/slides-109-iccrg-update-on-bbrv2-00)\] BBR Update: 1: BBR.Swift; 2: Scalable Loss Handling \- IETF 109 \- ICCRG (Nov 2020\)  
* \[[YouTube](https://youtu.be/Km7dzk6-4_E?t=5361)\] \[[slides](https://datatracker.ietf.org/meeting/110/materials/slides-110-iccrg-bbr-updates-00.pdf)\] BBR Internal Deployment, Code, Draft Plans \- IETF 110 \- ICCRG (Mar 2021\)  
* \[YouTube\] \[[slides](https://datatracker.ietf.org/meeting/112/materials/slides-112-iccrg-bbrv2-update-00)\] BBRv2 Update: Internet Drafts & Deployment Inside Google \- IETF 112 \- ICCRG (Nov 2021)  
* \[YouTube\] \[[slides](https://datatracker.ietf.org/meeting/112/materials/slides-112-iccrg-bbrv2-quic-update-00)\] BBRv2 Update: QUIC Tweaks and Internet Deployment \- IETF 112 ICCRG (Nov 2021)  
* \[[YouTube](https://youtu.be/u-91t6JfjmY?t=2828)\] \[[slides](https://datatracker.ietf.org/meeting/117/materials/slides-117-ccwg-bbrv3-algorithm-bug-fixes-and-public-internet-deployment-00)\] BBRv3: Algorithm Updates and Public Internet Deployment \- IETF 117 \- CCWG (Jul 2023\)  
* \[[YouTube](https://www.youtube.com/watch?v=ZVqQiA7h-W8&t=5378s)\] \[[slides](https://datatracker.ietf.org/meeting/119/materials/slides-119-ccwg-bbrv3-overview-and-google-deployment)\] BBRv3: Algorithm Overview and Google's Public Internet Deployment \- IETF 119 \- CCWG (Mar 2024\)  
* \[[YouTube](https://www.youtube.com/watch?v=QYiiaOYkfjo&t=1173s)\] \[[slides](https://datatracker.ietf.org/meeting/120/materials/slides-120-ccwg-bbrv3-ccwg-internet-draft-update-00)\] BBRv3: Internet Draft Update: draft-cardwell-ccwg-bbr-00 \- IETF 120 \- CCWG (Jul 2024\)


This is not an official Google product.
