

# Teaching-HEIGVD-SRX-2020-Laboratoire-IDS

**Ce travail de laboratoire est à faire en équipes de 2 personnes** (oui... en remote...). Je vous laisse vous débrouiller ;-)

**ATTENTION : Commencez par créer un Fork de ce repo et travaillez sur votre fork.**

Clonez le repo sur votre machine. Vous pouvez répondre aux questions en modifiant directement votre clone du README.md ou avec un fichier pdf que vous pourrez uploader sur votre fork.

**Le rendu consiste simplement à répondre à toutes les questions clairement identifiées dans le text avec la mention "Question" et à les accompagner avec des captures. Le rendu doit se faire par une "pull request". Envoyer également le hash du dernier commit et votre username GitHub par email au professeur et à l'assistant**

## Etudiants

Doran Kayoumi

Fabio da Silva Marques

## Table de matières

[Introduction](#introduction)

[Echéance](#echéance)

[Configuration du réseau](#configuration-du-réseau-sur-virtualbox)

[Installation de Snort](#installation-de-snort-sur-linux)

[Essayer Snort](#essayer-snort)

[Utilisation comme IDS](#utilisation-comme-un-ids)

[Ecriture de règles](#ecriture-de-règles)

[Travail à effectuer](#exercises)


## Echéance 

Ce travail devra être rendu le dimanche après la fin de la 2ème séance de laboratoire, soit au plus tard, **le 6 avril 2020, à 23h59.**


## Introduction

Dans ce travail de laboratoire, vous allez explorer un système de detection contre les intrusions (IDS) dont l'utilisation es très répandue grace au fait qu'il est gratuit et open source. Il s'appelle [Snort](https://www.snort.org). Il existe des versions de Snort pour Linux et pour Windows.

### Les systèmes de detection d'intrusion

Un IDS peut "écouter" tout le traffic de la partie du réseau où il est installé. Sur la base d'une liste de règles, il déclenche des actions sur des paquets qui correspondent à la description de la règle.

Un exemple de règle pourrait être, en language commun : "donner une alerte pour tous les paquets envoyés par le port http à un serveur web dans le réseau, qui contiennent le string 'cmd.exe'". En on peut trouver des règles très similaires dans les règles par défaut de Snort. Elles permettent de détecter, par exemple, si un attaquant essaie d'executer un shell de commandes sur un serveur Web tournant sur Windows. On verra plus tard à quoi ressemblent ces règles.

Snort est un IDS très puissant. Il est gratuit pour l'utilisation personnelle et en entreprise, où il est très utilisé aussi pour la simple raison qu'il est l'un des plus efficaces systèmes IDS.

Snort peut être exécuté comme un logiciel indépendant sur une machine ou comme un service qui tourne après chaque démarrage. Si vous voulez qu'il protège votre réseau, fonctionnant comme un IPS, il faudra l'installer "in-line" avec votre connexion Internet. 

Par exemple, pour une petite entreprise avec un accès Internet avec un modem simple et un switch interconnectant une dizaine d'ordinateurs de bureau, il faudra utiliser une nouvelle machine executant Snort et placée entre le modem et le switch. 


## Matériel

Vous avez besoin de votre ordinateur avec VirtualBox et une VM Kali Linux. Vous trouverez un fichier OVA pour la dernière version de Kali sur `//eistore1/cours/iict/Laboratoires/SRX/Kali` si vous en avez besoin.


## Configuration du réseau sur VirtualBox

Votre VM fonctionnera comme IDS pour "protéger" votre machine hôte (par exemple, si vous faites tourner VirtualBox sur une machine Windows, Snort sera utilisé pour capturer le trafic de Windows vers l'Internet).

Pour cela, il faudra configurer une réseau de la VM en mode "bridge" et activer l'option "Promiscuous Mode" dans les paramètres avancés de l'interface. Le mode bridge dans l'école ne vous permet pas d'accéder à l'Internet depuis votre VM. Vous pouvez donc rajouter une deuxième interface réseau à votre Kali configurée comme NAT. La connexion Internet est indispensable pour installer Snort mais pas vraiment nécessaire pour les manipulations du travail pratique.

Pour les captures avec Snort, assurez-vous de toujours indiquer la bonne interface dans la ligne de commandes, donc, l'interface configurée en mode promiscuous.

![Topologie du réseau virtualisé](images/Snort_Kali.png)


## Installation de Snort sur Linux

On va installer Snort sur Kali Linux. Si vous avez déjà une VM Kali, vous pouvez l'utiliser. Sinon, vous avez la possibilité de copier celle sur `eistore`.

La manière la plus simple c'est de d'installer Snort en ligne de commandes. Il suffit d'utiliser la commande suivante :

```
sudo apt update && apt install snort
```

Ceci télécharge et installe la version la plus récente de Snort.

Vers la fin de l'installation, on vous demande de fournir l'adresse de votre réseau HOME. Il s'agit du réseau que vous voulez protéger. Cela sert à configurer certaines variables pour Snort. Pour les manipulations de ce laboratoire, vous pouvez donner n'importe quelle adresse comme réponse.


## Essayer Snort

Une fois installé, vous pouvez lancer Snort comme un simple "sniffer". Pourtant, ceci capture tous les paquets, ce qui peut produire des fichiers de capture énormes si vous demandez de les journaliser. Il est beaucoup plus efficace d'utiliser des règles pour définir quel type de trafic est intéressant et laisser Snort ignorer le reste.

Snort se comporte de différentes manières en fonction des options que vous passez en ligne de commande au démarrage. Vous pouvez voir la grande liste d'options avec la commande suivante :

```
snort --help
```

On va commencer par observer tout simplement les entêtes des paquets IP utilisant la commande :

```
snort -v -i eth0
```

**ATTENTION : assurez-vous de bien choisir l'interface qui se trouve en mode bridge/promiscuous. Elle n'est peut-être pas eth0 chez-vous!**

Snort s'execute donc et montre sur l'écran tous les entêtes des paquets IP qui traversent l'interface eth0. Cette interface est connectée à l'interface réseau de votre machine hôte à travers le bridge de VirtualBox.

Pour arrêter Snort, il suffit d'utiliser `CTRL-C` (**attention** : il peut arriver de temps à autres que snort ne réponde pas correctement au signal d'arrêt. Dans ce cas-là, il faudra utiliser `kill` pour arrêter le process).

## Utilisation comme un IDS

Pour enregistrer seulement les alertes et pas tout le trafic, on execute Snort en mode IDS. Il faudra donc spécifier un fichier contenant des règles. 

Il faut noter que `/etc/snort/snort.config` contient déjà des références aux fichiers de règles disponibles avec l'installation par défaut. Si on veut tester Snort avec des règles simples, on peut créer un fichier de config personnalisé (par exemple `mysnort.conf`) et importer un seul fichier de règles utilisant la directive "include".

Les fichiers de règles sont normalement stockes dans le repertoire `/etc/snort/rules/`, mais en fait un fichier de config et les fichiers de règles peuvent se trouver dans n'importe quel repertoire. 

Par exemple, créez un fichier de config `mysnort.conf` dans le repertoire `/etc/snort` avec le contenu suivant :

```
include /etc/snort/rules/icmp2.rules
```

Ensuite, créez le fichier de règles `icmp2.rules` dans le repertoire `/etc/snort/rules/` et rajoutez dans ce fichier le contenu suivant :

`alert icmp any any -> any any (msg:"ICMP Packet"; sid:4000001; rev:3;)`

On peut maintenant executer la commande :

```
snort -c /etc/snort/mysnort.conf
```

Vous pouvez maintenant faire quelques pings depuis votre hôte et regarder les résultas dans le fichier d'alertes contenu dans le repertoire `/var/log/snort/`. 


## Ecriture de règles

Snort permet l'écriture de règles qui décrivent des tentatives de exploitation de vulnérabilités bien connues. Les règles Snort prennent en charge à la fois, l'analyse de protocoles et la recherche et identification de contenu.

Il y a deux principes de base à respecter :

* Une règle doit être entièrement contenue dans une seule ligne
* Les règles sont divisées en deux sections logiques : (1) l'entête et (2) les options.

L'entête de la règle contient l'action de la règle, le protocole, les adresses source et destination, et les ports source et destination.

L'option contient des messages d'alerte et de l'information concernant les parties du paquet dont le contenu doit être analysé. Par exemple:

```
alert tcp any any -> 192.168.1.0/24 111 (content:"|00 01 86 a5|"; msg: "mountd access";)
```

Cette règle décrit une alerte générée quand Snort trouve un paquet avec tous les attributs suivants :

* C'est un paquet TCP
* Emis depuis n'importe quelle adresse et depuis n'importe quel port
* A destination du réseau identifié par l'adresse 192.168.1.0/24 sur le port 111

Le text jusqu'au premier parenthèse est l'entête de la règle. 

```
alert tcp any any -> 192.168.1.0/24 111
```

Les parties entre parenthèses sont les options de la règle:

```
(content:"|00 01 86 a5|"; msg: "mountd access";)
```

Les options peuvent apparaître une ou plusieurs fois. Par exemple :

```
alert tcp any any -> any 21 (content:"site exec"; content:"%"; msg:"site
exec buffer overflow attempt";)
```

La clé "content" apparait deux fois parce que les deux strings qui doivent être détectés n'apparaissent pas concaténés dans le paquet mais à des endroits différents. Pour que la règle soit déclenchée, il faut que le paquet contienne **les deux strings** "site exec" et "%". 

Les éléments dans les options d'une règle sont traitées comme un AND logique. La liste complète de règles sont traitées comme une succession de OR.

## Informations de base pour le règles

### Actions :

```
alert tcp any any -> any any (msg:"My Name!"; content:"Skon"; sid:1000001; rev:1;)
```

L'entête contient l'information qui décrit le "qui", le "où" et le "quoi" du paquet. Ça décrit aussi ce qui doit arriver quand un paquet correspond à tous les contenus dans la règle.

Le premier champ dans le règle c'est l'action. L'action dit à Snort ce qui doit être fait quand il trouve un paquet qui correspond à la règle. Il y a six actions :

* alert - générer une alerte et écrire le paquet dans le journal
* log - écrire le paquet dans le journal
* pass - ignorer le paquet
* drop - bloquer le paquet et l'ajouter au journal
* reject - bloquer le paquet, l'ajouter au journal et envoyer un `TCP reset` si le protocole est TCP ou un `ICMP port unreachable` si le protocole est UDP
* sdrop - bloquer le paquet sans écriture dans le journal

### Protocoles :

Le champ suivant c'est le protocole. Il y a trois protocoles IP qui peuvent être analysez par Snort : TCP, UDP et ICMP.


### Adresses IP :

La section suivante traite les adresses IP et les numéros de port. Le mot `any` peut être utilisé pour définir "n'import quelle adresse". On peut utiliser l'adresse d'une seule machine ou un block avec la notation CIDR. 

Un opérateur de négation peut être appliqué aux adresses IP. Cet opérateur indique à Snort d'identifier toutes les adresses IP sauf celle indiquée. L'opérateur de négation est le `!`.

Par exemple, la règle du premier exemple peut être modifiée pour alerter pour le trafic dont l'origine est à l'extérieur du réseau :

```
alert tcp !192.168.1.0/24 any -> 192.168.1.0/24 111
(content: "|00 01 86 a5|"; msg: "external mountd access";)
```

### Numéros de Port :

Les ports peuvent être spécifiés de différentes manières, y-compris `any`, une définition numérique unique, une plage de ports ou une négation.

Les plages de ports utilisent l'opérateur `:`, qui peut être utilisé de différentes manières aussi :

```
log udp any any -> 192.168.1.0/24 1:1024
```

Journaliser le traffic UDP venant d'un port compris entre 1 et 1024.

--

```
log tcp any any -> 192.168.1.0/24 :6000
```

Journaliser le traffic TCP venant d'un port plus bas ou égal à 6000.

--

```
log tcp any :1024 -> 192.168.1.0/24 500:
```

Journaliser le traffic TCP venant d'un port privilégié (bien connu) plus grand ou égal à 500 mais jusqu'au port 1024.


### Opérateur de direction

L'opérateur de direction `->`indique l'orientation ou la "direction" du trafique. 

Il y a aussi un opérateur bidirectionnel, indiqué avec le symbole `<>`, utile pour analyser les deux côtés de la conversation. Par exemple un échange telnet :

```
log 192.168.1.0/24 any <> 192.168.1.0/24 23
```

## Alertes et logs Snort

Si Snort détecte un paquet qui correspond à une règle, il envoie un message d'alerte ou il journalise le message. Les alertes peuvent être envoyées au syslog, journalisées dans un fichier text d'alertes ou affichées directement à l'écran.

Le système envoie **les alertes vers le syslog** et il peut en option envoyer **les paquets "offensifs" vers une structure de repertoires**.

Les alertes sont journalisées via syslog dans le fichier `/var/log/snort/alerts`. Toute alerte se trouvant dans ce fichier aura son paquet correspondant dans le même repertoire, mais sous le fichier `snort.log.xxxxxxxxxx` où `xxxxxxxxxx` est l'heure Unix du commencement du journal.

Avec la règle suivante :

```
alert tcp any any -> 192.168.1.0/24 111
(content:"|00 01 86 a5|"; msg: "mountd access";)
```

un message d'alerte est envoyé à syslog avec l'information "mountd access". Ce message est enregistré dans `/var/log/snort/alerts` et le vrai paquet responsable de l'alerte se trouvera dans un fichier dont le nom sera `/var/log/snort/snort.log.xxxxxxxxxx`.

Les fichiers log sont des fichiers binaires enregistrés en format pcap. Vous pouvez les ouvrir avec Wireshark ou les diriger directement sur la console avec la commande suivante :

```
tcpdump -r /var/log/snort/snort.log.xxxxxxxxxx
```

Vous pouvez aussi utiliser des captures Wireshark ou des fichiers snort.log.xxxxxxxxx comme source d'analyse por Snort.

## Exercises

**Réaliser des captures d'écran des exercices suivants et les ajouter à vos réponses.**

### Essayer de répondre à ces questions en quelques mots :

**Question 1: Qu'est ce que signifie les "preprocesseurs" dans le contexte de Snort ?**

---

**Reponse :**  Le preprocesseur est un composant qui va examiner les paquets avant le moteur de détection. Par exemple, il peut examiner un paquet pour une activité suspecte.

---

**Question 2: Pourquoi êtes vous confronté au WARNING suivant `"No preprocessors configured for policy 0"` lorsque vous exécutez la commande `snort` avec un fichier de règles ou de configuration "home-made" ?**

---

**Reponse :**  Nous sommes confrontés à ce warning car nous n'avons chargé aucun preprocesseurr.

---

--

### Trouver votre nom :

Considérer la règle simple suivante:

alert tcp any any -> any any (msg:"Mon nom!"; content:"Rubinstein"; sid:4000015; rev:1;)

**Question 3: Qu'est-ce qu'elle fait la règle et comment ça fonctionne ?**

---

**Reponse :**  Pour chaque paquet `tcp` emis depuis n'importe quelle adresse et depuis n'importe quel port qui a pour destination n'importe qu'elle adresse et n'importe quel port, snort vérifier s'il contient le texte `Rubinstein`. S'il l'a détecté, il lève une alert avec comme message `Mon nom!`.

---

Utiliser un éditeur et créer un fichier `myrules.rules` sur votre répertoire home. Rajouter une règle comme celle montrée avant mais avec votre nom ou un mot clé de votre préférence. Lancer snort avec la commande suivante :

```
sudo snort -c myrules.rules -i eth0
```

**Question 4: Que voyez-vous quand le logiciel est lancé ? Qu'est-ce que tous les messages affichés veulent dire ?**

---

**Reponse :**  

```
root@kali:~# snort -c myrules.rules -i eth0
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "myrules.rules"
Tagged Packet Limit: 256
Log directory = /var/log/snort

+++++++++++++++++++++++++++++++++++++++++++++++++++
Initializing rule chains...
1 Snort rules read
    1 detection rules
    0 decoder rules
    0 preprocessor rules
1 Option Chains linked into 1 Chain Headers
0 Dynamic rules
+++++++++++++++++++++++++++++++++++++++++++++++++++

+-------------------[Rule Port Counts]---------------------------------------
|             tcp     udp    icmp      ip
|     src       0       0       0       0
|     dst       0       0       0       0
|     any       1       0       0       0
|      nc       0       0       0       0
|     s+d       0       0       0       0
+----------------------------------------------------------------------------

+-----------------------[detection-filter-config]------------------------------
| memory-cap : 1048576 bytes
+-----------------------[detection-filter-rules]-------------------------------
| none
-------------------------------------------------------------------------------

+-----------------------[rate-filter-config]-----------------------------------
| memory-cap : 1048576 bytes
+-----------------------[rate-filter-rules]------------------------------------
| none                                                
-------------------------------------------------------------------------------                                                          
+-----------------------[event-filter-config]----------------------------------           
| memory-cap : 1048576 bytes                                                               
+-----------------------[event-filter-global]----------------------------------           
+-----------------------[event-filter-local]-----------------------------------           
| none                                                      
+-----------------------[suppression]------------------------------------------           
| none                                                                                     
-------------------------------------------------------------------------------           Rule application order: activation->dynamic->pass->drop->sdrop->reject->alert->log         Verifying Preprocessor Configurations!                                                     
[ Port Based Pattern Matching Memory ]                                                                                                                                                                                                     
+-[AC-BNFA Search Info Summary]------------------------------                             
| Instances        : 1                                                                     
| Patterns         : 1                                                                     
| Pattern Chars    : 5                                                                     
| Num States       : 5                                                                     
| Num Match States : 1                                                                     
| Memory           :   1.56Kbytes                                                         
|   Patterns       :   0.04K                                                               
|   Match Lists    :   0.07K                                                               
|   Transitions    :   1.05K                                                               
+-------------------------------------------------                                         pcap DAQ configured to passive.                                                           Acquiring network traffic from "eth0".                                                     Reload thread starting...
Reload thread started, thread 0x7f23546c7700 (1832)
Decoding Ethernet

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

Commencing packet processing (pid=1797)
```

Snort nous indique toutes les règles et configurations qu'il a chargées.

---

Aller à un site web contenant dans son text votre nom ou votre mot clé que vous avez choisi (il faudra chercher un peu pour trouver un site en http...).

**Question 5: Que voyez-vous sur votre terminal quand vous visitez le site ?**

---

**Reponse :**  Mise à part le grand nombre de warnings `No preprocessors configured for policy 0`, rien n'est affiché dans mon terminal. Ceci est normal car les alertes vont dans le fichier `/var/log/snort/alert`.

---

Arrêter Snort avec `CTRL-C`.

**Question 6: Que voyez-vous quand vous arrêtez snort ? Décrivez en détail toutes les informations qu'il vous fournit.**

---

**Reponse :**  Snort affiche les statistiques de son analyse. Qui est découpé en 5 parties.

Dans cette première partie, Snort pour indiquer combien de temps il a tourné, le nombre de paquets traités ainsi que le nombre traité par minute et par seconde.

```
===============================================================================
Run time for packet processing was 66.55255 seconds
Snort processed 1587 packets.
Snort ran for 0 days 0 hours 1 minutes 6 seconds
   Pkts/min:         1587
   Pkts/sec:           24
===============================================================================
```

La deuxième partie nous indique l'utilisation de la mémoire.

```
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       2293760
  Bytes in mapped regions (hblkhd):      17252352
  Total allocated space (uordblks):      2066576
  Total free space (fordblks):           227184
  Topmost releasable block (keepcost):   69600
===============================================================================
```

Dans cette troisième partie, l'on peut voir ce qui s'est passé avec les paquets traités. S'ils ont été analysés, annulés, etc...

```
===============================================================================
Packet I/O Totals:
   Received:         1604
   Analyzed:         1587 ( 98.940%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:           17 (  1.060%)
   Injected:            0
===============================================================================
```

Ici les paquets sont regroupés selon le protocole utilisé.

```
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:         1587 (100.000%)
       VLAN:           15 (  0.945%)
        IP4:          989 ( 62.319%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:          193 ( 12.161%)
        TCP:          772 ( 48.645%)
        IP6:          529 ( 33.333%)
    IP6 Ext:          540 ( 34.026%)
   IP6 Opts:           18 (  1.134%)
      Frag6:            0 (  0.000%)
      ICMP6:           34 (  2.142%)
       UDP6:           63 (  3.970%)
       TCP6:          425 ( 26.780%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:           61 (  3.844%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:           24 (  1.512%)
   IP6 Disc:            7 (  0.441%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:           31 (  1.953%)
      Other:            8 (  0.504%)
Bad Chk Sum:          447 ( 28.166%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:         1587
===============================================================================
```

Cette dernière section, nous montre les statistiques des "actions" que Snort a dû faire. 

```
===============================================================================
Action Stats:
     Alerts:           16 (  1.008%)
     Logged:           16 (  1.008%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:         1587 ( 98.940%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
```

---


Aller au répertoire /var/log/snort. Ouvrir le fichier `alert`. Vérifier qu'il y ait des alertes pour votre nom ou mot choisi.

**Question 7: A quoi ressemble l'alerte ? Qu'est-ce que chaque élément de l'alerte veut dire ? Décrivez-la en détail !**

---

**Reponse :**  

```
[**] [1:4000015:1] Hey! Stop that! [**]
[Priority: 0] 
04/03-17:20:50.977068 128.142.128.245:80 -> 192.168.1.120:46206
TCP TTL:50 TOS:0x0 ID:14656 IpLen:20 DgmLen:1500 DF
***A**** Seq: 0x97842713  Ack: 0x2BF22EDB  Win: 0xB0  TcpLen: 20
```



---


--

### Detecter une visite à Wikipedia

Ecrire une règle qui journalise (sans alerter) un message à chaque fois que Wikipedia est visité **DEPUIS VOTRE** station. **Ne pas utiliser une règle qui détecte un string ou du contenu**.

**Question 8: Quelle est votre règle ? Où le message a-t'il été journalisé ? Qu'est-ce qui a été journalisé ?**

---

**Reponse :**  

Avant de pouvoir écrire une règle qui détect a chaque fois que l'on visite Wikipedia, il a fallu trouver son adresse IP. En faisant un `ping wikipedia.org`, on trouve l'adresse que notre station utilise pour communiquer avec. Dans notre cas, elle utilise l'adresse IPv6 de Wikipedia `2620:0:862:ed1a::1`.

Notre machine faisant les requêtes en IPv6, nous avons dû utiliser son adresse IPv6 comme source.

```
log tcp [2a02:120b:c3fc:9eb0:47b8:1f3e:9a24:5f7c] any -> [2620:0:862:ed1a::1] any (msg: "Wikipedia visited"; sid: 4000016; rev:1;)
```

Le message a été journalisé dans une capture pcap dans `/var/log/snort/`.

Ce fichier contient toutes les requêtes ayant comme destination Wikipedia.

Voici un extrait de son contenu: 

```
10:47:58.532469 IP6 doran-pc.home.35342 > text-lb.esams.wikimedia.org.https: Flags [S], seq 59662200, win 64952, options [mss 1412,sackOK,TS val 1049226108 ecr 0,nop,wscale 7], length 0
10:47:58.556172 IP6 doran-pc.home.35342 > text-lb.esams.wikimedia.org.https: Flags [.], ack 2551663486, win 508, options [nop,nop,TS val 1049226132 ecr 3103013427], length 0
10:47:58.557001 IP6 doran-pc.home.35342 > text-lb.esams.wikimedia.org.https: Flags [P.], seq 0:595, ack 1, win 508, options [nop,nop,TS val 1049226133 ecr 3103013427], length 595

```

---

--

### Detecter un ping d'un autre système

Ecrire une règle qui alerte à chaque fois que votre système reçoit un ping depuis une autre machine (je sais que la situation actuelle du Covid-19 ne vous permet pas de vous mettre ensemble... utilisez votre imagination pour trouver la solution à cette question !). Assurez-vous que **ça n'alerte pas** quand c'est vous qui envoyez le ping vers un autre système !

**Question 9: Quelle est votre règle ?**

---

**Reponse :**  

```
alert icmp any any -> 192.168.1.151 any (msg: "Pinged"; itype:8; sid: 4000017; rev:1;)
```

---


**Question 10: Comment avez-vous fait pour que ça identifie seulement les pings entrants ?**

---

**Reponse :**  

Nous avons défini que nous voulions avoir une alerte seulement les paquets `ICMP` ayant comme destination notre système grâce à l'opérateur `->`. De plus nous avons ajouté l'option `itype:8` pour que snort ne nous alerte seulement quand il détecte des requêtes `ICMP echo request` ceci afin d'alléger les logs.

---


**Question 11: Où le message a-t-il été journalisé ?**

---

**Reponse :**  

L'alerte est écrite dans le ficheir `/var/log/snort/alert` et le paquet est enregistré dans le fichier `/var/log/snort/snort.log.xxx`.

---

**Question 12: Qu'est-ce qui a été journalisé ?**

---

**Reponse :**  

Dans `/var/log/snort/alert`  on trouve l'alerte qui a été levé par Snort:

```
[**] [1:4000017:1] Pinged [**]
[Priority: 0] 
04/04-14:35:25.527080 192.168.1.120 -> 192.168.1.151
ICMP TTL:64 TOS:0x0 ID:29897 IpLen:20 DgmLen:84 DF
Type:8  Code:0  ID:3374   Seq:1  ECHO
```



Dans `/var/log/snort/snort.lop.xxx` les paquets qui ont causé l'alerte:

```
reading from file snort.log.1586007316, link-type EN10MB (Ethernet)
14:35:25.527080 IP kali.home > doran-pc.home: ICMP echo request, id 3374, seq 1, length 64
14:35:26.542968 IP kali.home > doran-pc.home: ICMP echo request, id 3374, seq 2, length 64
14:35:27.566965 IP kali.home > doran-pc.home: ICMP echo request, id 3374, seq 3, length 64
14:35:28.591072 IP kali.home > doran-pc.home: ICMP echo request, id 3374, seq 4, length 64
14:35:29.614929 IP kali.home > doran-pc.home: ICMP echo request, id 3374, seq 5, length 64
14:35:30.639157 IP kali.home > doran-pc.home: ICMP echo request, id 3374, seq 6, length 64
```

---

--

### Detecter les ping dans les deux sens

Modifier votre règle pour que les pings soient détectés dans les deux sens.

**Question 13: Qu'est-ce que vous avez modifié pour que la règle détecte maintenant le trafic dans les deux senses ?**

---

**Reponse :**  

La règle avec les modifications demandées:

```
alert icmp any any <> 192.168.1.151 any (msg: "Pinged"; itype:8; sid: 4000017; rev:1;)
```

Nous avons changé l'opérateur `->` par `<>` ceci pour indiquer à snort que nous voulons les requêtes `ICMP` dans les deux sens.

---


--

### Detecter une tentative de login SSH

Essayer d'écrire une règle qui Alerte qu'une tentative de session SSH a été faite depuis la machine d'un voisin (je sais que la situation actuelle du Covid-19 ne vous permet pas de vous mettre ensemble... utilisez votre imagination pour trouver la solution à cette question !). Si vous avez besoin de plus d'information sur ce qui décrit cette tentative (adresses, ports, protocoles), servez-vous de Wireshark pour analyser les échanges lors de la requête de connexion depuis votre voisi.

**Question 14: Quelle est votre règle ? Montrer la règle et expliquer en détail comment elle fonctionne.**

---

**Reponse :**  

```
alert tcp any any -> 192.168.1.151 22 (msg: "SSH connection request"; flags:S; sid:4000018; rev:1;)
```

Cette règle détecte les requêtes ayant comme destination notre système avec le port `22` ce qui correspond à une connection ssh. Nous y avons ajouté l'option `flags:S` afin de ne retenir que les demandes de connexions ou plutôt les requêtes `SYN`.

**Note: Pour une chose qui nous échappe, notre règle ne fonctionne pas alors qu'il nous semble qu'elle soit correcte.**

---


**Question 15: Montrer le message d'alerte enregistré dans le fichier d'alertes.** 

---

**Reponse :**  

````
[**] [1:4000018:1] SSH connection request [**]
[Priority: 0] 
04/04-21:56:54.343870 192.168.1.120:60020 -> 192.168.1.151:22
TCP TTL:64 TOS:0x10 ID:0 IpLen:20 DgmLen:52 DF
***A**** Seq: 0x4924D5F2  Ack: 0x6F70D97B  Win: 0x489  TcpLen: 32
TCP Options (3) => NOP NOP TS: 2016553581 231678472 
````

**Note: Nous avons retiré le option `flags:S` et snork a détecté la déconnexion. Mais l'alerte que snork aurait du levé lors d'une tentative de connexion serai similaire à celle-ci. L'une des différences étant qu'il y aurait un `SYN` au lieu du `ACK`.**

---

--

### Analyse de logs

Lancer Wireshark et faire une capture du trafic sur l'interface connectée au bridge. Générez du trafic avec votre machine hôte qui corresponde à l'une des règles que vous avez ajouté à votre fichier de configuration personnel. Arrêtez la capture et enregistrez-la dans un fichier.

**Question 16: Quelle est l'option de Snort qui permet d'analyser un fichier pcap ou un fichier log ?**

---

**Reponse :**  `-r <file>`

---

Utiliser l'option correcte de Snort pour analyser le fichier de capture Wireshark.

**Question 17: Quelle est le comportement de Snort avec un fichier de capture ? Y-a-t'il une difference par rapport à l'analyse en temps réel ?**

---

**Reponse :**  Snort se comporte de la manière que s'il faisait une analyse en temps réel. La différence est qu'il est beaucoup plus rapide en lisant un fichier.

---

**Question 18: Est-ce que des alertes sont aussi enregistrées dans le fichier d'alertes?**

---

**Reponse :**  Oui

---

--

### Contournement de la détection

Faire des recherches à propos des outils `fragroute` et `fragtest`.

**Question 20: A quoi servent ces deux outils ?**

---

**Reponse :**  

Ils servent à contourner des systèmes de détection d'intrusion.

---


**Question 21: Quel est le principe de fonctionnement ?**

---

**Reponse :**  

Les paquets envoyés sont fragmentés en plusieurs petits paquets. Bien sûr d'autre manipulations peuvent être appliquées aux fragments comme par exemple les réordonner.

---

**Question 22: Qu'est-ce que le `Frag3 Preprocessor` ? A quoi ça sert et comment ça fonctionne ?**

---

**Reponse :**  

C'est le module proposé par snort afin de "contrer" les outils précédent (voire d'autre outil faisant des choses similaires). Il va essayer de défragmenter les paquets afin de permettre à snort de les analyser.

---


Reprendre l'exercice de la partie [Trouver votre nom](#trouver-votre-nom-). Essayer d'offusquer la détection avec `fragroute`.


**Question 23: Quel est le résultat de votre tentative ?**

---

**Reponse :**  

Snort ne détecte pas la requête qui est effectuée et donc ne lève pas d'alerte.

---


Modifier le fichier `myrules.rules` pour que snort utiliser le `Frag3 Preprocessor` et refaire la tentative.

**Question 24: Quel est le résultat ?**

---

**Reponse :**  

Snort arrive a détecter la requête.

```
root@kali:~# snort -A console -q -c myrules.rules -i eth0
04/04-21:13:26.513798  [**] [1:4000015:1] Hey! Stop that! [**] [Priority: 0] {TCP} 192.168.1.120:38762 -> 80.74.149.75:80
04/04-21:13:26.541958  [**] [1:4000015:1] Hey! Stop that! [**] [Priority: 0] {TCP} 80.74.149.75:80 -> 192.168.1.120:38762
```

---

**Question 25: A quoi sert le `SSL/TLS Preprocessor` ?**

---

**Reponse :**  

Il va analyser la partie non chiffrée (le header) d'une requête sécurisée. 

---

**Question 26: A quoi sert le `Sensitive Data Preprocessor` ?**

---

**Reponse :**  

Elle sert à filter les données personnelles. e.g. numéro de carte de crédit, adresse email, etc..

---

### Conclusions


**Question 27: Donnez-nous vos conclusions et votre opinion à propos de snort**

---

**Reponse :**  Ce laboratoire nous a permis de mettre en pratique la théorie que nous avons vue en cours...uh enfin à la maison... et de découvir Snort. 

Snort est un outil très puissant et asser aisé d'utilisation. La grosse difficulté réside dans l'écriture de règles. Pour des éléments "simples" comme la détection de ping cela reste asser trivial mais dès que l'on souhaite faire des choses plus poussées, la configuration devient très vite compliquée.

Tout au long de ce laboratoire, nous avons eu quelques soucis (e.g. la parti SSH) mais elles sont vraisemblablement liées à cette situation exeptionnelle dans laquelle nous nous trouvons actuellement.

---

<sub>This guide draws heavily on http://cs.mvnu.edu/twiki/bin/view/Main/CisLab82014</sub>