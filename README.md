# Waterfall Chart Tool

Turn a packet capture into a clean, annotated waterfall (ladder) diagram — or draw one from scratch.
Everything runs in your browser from plain HTML/JS files: no server, no install, no upload.

## Quick start

1. Open `index.html` in Chrome, Safari, Firefox or Edge (double-click it, or drag it onto the browser).
2. Click **Open capture** (or drop a file onto the page) and pick a `.pcap` or `.pcapng`.
   Try `samples/sample.pcap`.
3. Tidy it up: pick a granularity, hide what you don't need, rename hosts, add comments.
4. **Export SVG / PNG** for the picture, **Save project** to keep your edits (`.waterfall.json`).

To see a diagram built from scratch, use **Open project** on `samples/from-scratch-example.waterfall.json`.

## What the chart shows

**Waterfall view** — hosts are vertical lanes, time runs down the page, each packet or message is an
arrow from sender to receiver with the decoded summary above it and the size below it. Long pauses are
marked with a dashed divider. Comments appear in a notes column on the right.

**Timeline view** — one row per event with a horizontal bar on a time axis (like a browser network
waterfall). Most useful at Flow granularity to compare connection durations.

### Granularity (how much detail)

| Level | One row per … | Good for |
|---|---|---|
| **Packet** | captured packet | exact sequence, handshakes, retransmissions |
| **Message** | run of segments in one direction (pure ACKs dropped) | application-level exchange, e.g. an HTTP response that spans 30 segments |
| **Flow** | connection (5-tuple), from the initiator | what connections a host made, how long they took |
| **Hosts** | pair of hosts, all their traffic combined | the big picture |

Edits you make at packet level (comments, renames, colours) carry up to the coarser levels.

### Lanes: one per host, or one per host : port

By default every address gets one lane, and traffic from a host to itself (for example a local
service on 127.0.0.1) is drawn as a loop on that lane. Switch **Lanes** to *One per host : port*
and each address:port pair becomes its own lane, so `127.0.0.1:52000 → 127.0.0.1:8080` reads like a
conversation between two parties. Naming or hiding the plain address in the Hosts tab applies to all
of its port lanes (a lane named from its address shows as `Laptop:8080`); each port lane can also be
named on its own. Try `samples/loopback.pcap`.

Lane spacing is a minimum: gaps grow automatically so the labels between neighbouring lanes are not
cut off (turn off *Widen lanes so labels fit* if you prefer fixed spacing).

### Decoded protocols

Ethernet (with VLAN), Linux cooked capture, loopback, raw IP, 802.11 addresses; IPv4, IPv6 (with
extension headers), ARP; TCP (flags, relative seq/ack, options), UDP, ICMP, ICMPv6, IGMP; DNS / mDNS /
LLMNR (questions and answers), HTTP/1.x (request line, host, status), TLS (version, handshake messages,
SNI, ALPN, encrypted-handshake detection), QUIC (long/short header), DHCP, NTP, SSH, SSDP.
Anything else is shown as its transport or EtherType.

## Making it readable

* **Hosts tab** — give each address a display name (the lane shows the name with the address beneath),
  pick a colour marker, hide a host and all of its traffic, reorder lanes, or sort lanes by first seen /
  local first / busiest. Clicking a lane header in the chart jumps to that host.
* **Click a row** — the inspector on the right lets you change its label, add a comment, give it its own
  colour, or hide it. Decoded fields for the packet are listed underneath. `Delete` hides the selected row,
  `↑`/`↓` move the selection, `Esc` deselects.
* **Drag over rows** — in the waterfall, drag up or down across the rows you care about (in the
  timeline, drag left or right along the time axis). A popover offers **Keep only this range**, which
  crops the chart to that time window and cuts everything else out (a "Cropped to …" chip in the
  toolbar restores the full capture with ×), or **Hide these rows**, which hides just the selection.
* **Events tab** — a checklist of the rows on the current page; untick to hide, click to select.
* **Display filter** — space-separated terms that all have to match: plain text searches labels, hosts,
  protocols and comments; `host:` `src:` `dst:` `port:` `proto:` `label:` `comment:` narrow a term; a
  leading `-` excludes. Example: `tls -ack host:10.0.0.5`.
* **Chart tab toggles** — hide pure ACKs, hide TCP handshake/teardown, show hidden rows faded (to bring
  them back), comments column, sizes, ports, legend; tick protocols on/off and change their colours;
  set a time window and page size for big captures; adjust lane spacing, row height, font size and
  **Fit lanes to window**; even or time-scaled row spacing; relative / clock / delta time labels.
* **Zoom** controls in the chart toolbar only affect the screen; exports are always full size.

## Drawing a diagram from scratch

Click **New blank**, then use the **Add** tab:

* **Add a host** — an identifier (anything you like) and a display name. Hosts typed into an event
  form are created automatically too.
* **Add an event** — time, from/to, protocol, ports, size, label and an optional comment. With
  *auto-advance* on, the time field steps forward after each event so you can type a sequence quickly.
* **Insert a template** — drops in a ready-made exchange between two hosts (A = client, B = server):
  TCP handshake, TCP close, DNS lookup, TLS 1.2 / 1.3 handshake, HTTP request/response, full HTTPS page
  load, ICMP ping, DHCP lease, ARP, QUIC, SSH session start.
* Manually added events can be edited in the inspector (time, hosts, protocol, label, …), duplicated or
  deleted. You can also add hand-written events to a real capture to explain what is going on.

## Files

```
index.html            the app (open this)
css/style.css         UI styling, light and dark
js/pcap.js            pcap / pcapng reader and protocol decoders
js/model.js           events, granularity, annotations, filters
js/render.js          SVG rendering (waterfall + timeline), SVG/PNG export
js/app.js             UI, editing, project save/load, templates
samples/              sample captures (sample.pcap/.pcapng, loopback.pcap) and a from-scratch example project
tools/make_sample_pcap.py     regenerates samples/sample.pcap (python3, no dependencies)
tools/make_loopback_pcap.py   regenerates samples/loopback.pcap
```

A project file (`*.waterfall.json`) contains the decoded packets plus every edit, so it re-opens
without the original capture. Nothing ever leaves the browser.

## Serving it (optional)

If you serve the folder over HTTP (e.g. `python3 -m http.server`), URL parameters work:
`index.html?load=samples/sample.pcap&granularity=message&view=timeline&theme=dark&hideAcks=1&laneBy=port`.
Any setting name from the Chart tab can be passed this way.

## Limits

* Very large captures: rendering is paged (default 400 rows a page); use Message or Flow granularity,
  filters and the time window to zoom in. Parsing a 100 MB file takes a few seconds.
* Protocols are recognised by port and payload heuristics; traffic on unusual ports shows as TCP/UDP.
* TCP streams are not reassembled across segments, so only the first segment of an HTTP message or TLS
  record is decoded in depth (the rest are shown as continuation data and merged at Message level).
