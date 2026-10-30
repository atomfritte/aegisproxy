**AegisProxy: Container-Image-Firewall (OCI/Docker)**

Stand: 30.10.2026. Dieses Dokument ist ein Produkt- und Architekturkonzept. Es beschreibt die Ausweitung der in AegisProxy 3.0 implementierten **Paket-Firewall** (npm, PyPI, NuGet, PowerShell Gallery) auf **Container-Images** (Docker Hub, GHCR, GCR, ECR, Quay, Azure CR, private Registries). Die Image-Funktionen sind noch nicht implementiert. Ausgangspunkt ist die vorhandene 3.0-Engine (`internal/packages`, `internal/coordinator`, `internal/sandboxworker`, Data-Plane-Gate `data-plane/aegis_dp/packages.py`) und das Konzept [package-supply-chain-concept.de.md](package-supply-chain-concept.de.md).

**Die Idee ergibt Sinn — ein Image ist ein Bündel von Paketen**

Ein Container-Image ist kein neues Problem, sondern eine Zusammenfassung bekannter: Es besteht aus einem oder mehreren **Base-Images**, einer Reihe von **Layern** und dem darin enthaltenen **Software-Bestand** — Betriebssystempaketen (apk/dpkg/rpm) und Sprachpaketen (genau npm/PyPI/NuGet, die wir bereits auflösen und bewerten). Die Freigabeentscheidung ist dieselbe wie bei Bibliotheken: eine konkrete, unveränderliche Fassung beziehen, ihre Artefakte prüfen und entscheiden, welche Projekte sie unter welchen Bedingungen verwenden dürfen. Images sind dafür sogar günstiger gebaut als Bibliotheken, weil sie **inhaltsadressiert** sind: Jeder Pull referenziert einen `sha256:…`-Digest. „Nur freigegebene Digests sind ziehbar" ist eine schärfere und ehrlichere Aussage als das Metadaten-Filtern bei npm.

Das rückwirkende Produktziel bleibt dasselbe und wird besonders wertvoll: **Welche Hosts/Cluster haben ein inzwischen betroffenes Image (bzw. einen betroffenen Layer) gezogen?** Die 3.0-Receiver-Ansicht (`/packages/receivers`) wird dafür um Image-Digests und Layer-Digests erweitert.

**Was wir wiederverwenden — und was neu ist**

| Baustein | Status |
|---|---|
| Assessment-Modell, Advisory/CVSS (`internal/packages/advisory`), Regeln + Karenz (`rules.go`), Freigaben/Sperren, Receiver-Ansicht, Review-Konsole | **wiederverwendbar**, Image als weiteres „Ökosystem" (`oci`) |
| Sprachpaket-Resolver (npm/PyPI/NuGet) für den Image-Inhalt | **wiederverwendbar** |
| Sigstore-Verifier (`internal/packages/provenance`) | **wiederverwendbar** → cosign-Image-Signaturen und -Attestationen, gleicher Public-Good-Trust-Root |
| Sandbox-Worker mit Docker-Treiber (`internal/sandboxworker`), URL-/Syscall-/Datei-Mitschnitt | **wiederverwendbar** — die Analyse-Einheit *ist* hier ein Container |
| Re-Audit/Watch-Loop + Alerts (`internal/coordinator`) | **wiederverwendbar** — Digests gegen aktuelle Advisories nachprüfen |
| Registry-v2-Gate (Manifest/Blob-Abruf abfangen, per Digest freigeben) | **neu** |
| OS-Paket-Resolver (apk / dpkg / rpm) + SBOM-Erzeugung | **neu** |
| Base-Image-/Layer-Graph und dessen Darstellung | **neu** |

Grob bleiben ~60–70 % der Engine bestehen; neu sind im Wesentlichen der Gate-Pfad, der OS-Paketstand und die Image-Graph-Auflösung.

**Das Gate: OCI Distribution (Registry v2) transparent abfangen**

Der Client zieht ein Image über die standardisierte Registry-API, dieselben Hosts laufen bereits durch den Proxy:

1. `GET /v2/<name>/manifests/<ref>` — Manifest-Liste (Multi-Arch) bzw. Image-Manifest. `<ref>` ist ein Tag **oder** ein Digest.
2. `GET /v2/<name>/manifests/<digest>` — das plattformspezifische Manifest (Config-Digest + Layer-Digests).
3. `GET /v2/<name>/blobs/<digest>` — Config-Blob (JSON) und Layer-Blobs (komprimierte Tarballs).

Das Gate entscheidet **pro Digest**: Ein freigegebenes Image ist die Menge seiner freigegebenen Config- und Layer-Digests. Der Enforcement-Modus ist „Pull des freigegebenen Digests erlauben, alles andere ablehnen" — kein Metadaten-Umschreiben wie bei npm, sondern eine Allow/Deny-Entscheidung auf Manifest/Blob-Ebene. Weil Tags veränderlich sind, pinnt die Policy **Digests**; Tags werden nur als Anfrageform aufgelöst und protokolliert. Unbekannte Digests lösen (wie bei Bibliotheken) einen Request aus oder werden abgelehnt, je nach Modus (`off` / `monitor` / `enforce`).

Praktische Punkte, die wir ehrlich einplanen müssen:

- **Authentifizierung:** Registries nutzen Bearer-Token-Flows (`WWW-Authenticate` → Token-Endpunkt). Das Gate muss den Flow durchreichen, nicht brechen.
- **Größe:** Layer sind groß (oft hunderte MB). Der vorhandene Streaming-Hash-Pin und die Size-Limits der 3.0-Artefaktprüfung müssen für Images höher und streaming-fähig ausgelegt sein; Blobs werden im Durchlauf gehasht, nicht gepuffert.
- **Multi-Arch:** Eine Manifest-Liste verweist auf mehrere plattformspezifische Manifeste; Freigaben gelten je Plattform-Digest.
- **Mirrors/Pull-Through:** Viele Umgebungen nutzen Registry-Mirrors; die Host-Konfiguration je Ökosystem (`hosts`/`file_hosts`) deckt das ab.

**Der Image-Graph: Base-Images, Layer, Inhalt**

Analog zum Abhängigkeitsgraph einer Bibliothek lösen wir für ein Image auf:

- **Base-Image(s)** über `org.opencontainers.image.base.name`/`…base.digest`-Labels bzw. die `history`/`rootfs`-Angaben der Image-Config. So lässt sich „dieses App-Image erbt eine verwundbare `debian:bookworm`-Schicht" sichtbar machen.
- **Layer** als inhaltsadressierte Knoten (Digest, Größe, erzeugender Build-Schritt).
- **Software im Image** per SBOM: OS-Pakete (apk/dpkg/rpm — **neue Resolver/Parser**) und Sprachpakete (**bestehende Resolver**). Erzeugung wahlweise über einen eingebauten Scanner-Durchlauf oder, falls vorhanden, eine mitgelieferte SBOM-Attestation (SPDX/CycloneDX via cosign).

Das Ergebnis ist ein Graph, dessen Knoten sich exakt mit dem vorhandenen `PackageAssessment` bewerten lassen — CVEs je Komponente, Severity/CVSS, Malware-Verdikt.

**Prüfung: Advisories, Signaturen, Datum, Verhalten**

- **Advisories/Scan:** Der SBOM-Bestand wird gegen die konfigurierten Quellen geprüft (OSV deckt OS- und Sprachökosysteme ab). Ergänzend lassen sich etablierte Image-Scanner einbinden (Trivy, Grype, Syft/Scout, Clair) — ihre Befunde mappen auf dasselbe Advisory-Modell. OS-Distro-Advisories (Debian/Alpine/RHEL-Security-Tracker) liefern den korrekten „fixed-in"-Kontext.
- **Signaturen/Herkunft:** cosign-Signaturen und -Attestationen (keyless/Fulcio oder Schlüssel), SLSA-Provenance und SBOM-Attestationen — verifiziert über den bereits vorhandenen Sigstore-Verifier. Für ältere Setups optional Docker Content Trust (Notary v1).
- **Datum/Karenz:** Die Image-Config trägt ein `created`-Datum; die bestehende Karenz-Logik gilt für „neuer Tag/Digest" unverändert. Regel: neue Image-Versionen automatisch freigeben, aber erst nach Karenz und nur ohne offene Befunde.
- **Verhalten (Sandbox):** Der Docker-Treiber des Sandbox-Workers führt das Image kontrolliert aus und zeichnet — wie bei Paketen — alle **Web-URLs/DNS/Verbindungen**, **Syscalls**, Prozesse und Dateizugriffe auf. Für Images ist das besonders natürlich, weil die Analyse-Einheit ohnehin ein Container ist. Ehrlich bleibt: ein unauffälliger Lauf ist kein Entlastungsbeweis (zeit-/trigger-gesteuerter Schadcode).

**Rückverfolgung: wer hat welches Image/Layer gezogen?**

Die Data-Plane schreibt pro Pull einen Telemetrie-Datensatz mit Image-Referenz, aufgelöstem Digest, Layer-Digests und stabiler Server-/Workload-Identität. Die Receiver-Abfrage beantwortet dann: „Welche Hosts haben `repo@sha256:…` oder einen Layer `sha256:…` gezogen?" — inklusive Treffern aus Pull-Through-Caches. Gleiche Einschränkung wie in 3.0: Das In-Memory-Fenster ist begrenzt; die vollständige Historie liegt im Log-Export/SIEM.

**Welchen Schutz wir tatsächlich erreichen — und welchen nicht**

| Bedrohung | Beitrag der Image-Firewall |
|---|---|
| Bekannte verwundbare OS-/Sprachkomponente im Image | SBOM gegen aktuelle Advisories prüfen; betroffene Digests sperren; Re-Audit bestehender Freigaben |
| Bösartiges/kompromittiertes Base- oder App-Image | Signatur/Provenance prüfen, Inhalt bewerten, Verhalten beobachten, nur freigegebene Digests ausliefern |
| Mutiertes Tag (`:latest` zeigt plötzlich woanders hin) | Policy pinnt Digests; ein neuer Digest hinter bekanntem Tag erzwingt neue Freigabe |
| Nachladen von Binärcode zur Laufzeit | Egress-Regeln + Sandbox-Mitschnitt der URLs/Syscalls; Freigabe ≠ Laufzeitfreibrief |
| Rückfrage nach einem Vorfall | Receiver-Ansicht: welche Hosts/Cluster den betroffenen Digest/Layer gezogen haben |

Was die Image-Firewall **nicht** leistet: Sie entfernt kein bereits laufendes Image, stoppt keinen laufenden Container und ersetzt keine Runtime-Security (Admission-Controller, Laufzeit-Sensorik im Cluster). Sie kontrolliert den **Bezug** und macht Betroffenheit nachvollziehbar — die Durchsetzung im Cluster (z. B. „nur freigegebene Digests dürfen starten") ist eine ergänzende, separate Integration (OPA/Gatekeeper, Kyverno, Admission-Webhook), die auf denselben Freigabedaten aufsetzen kann.

**Vorgeschlagene Stufen**

1. **MVP — Sichtbarkeit (monitor):** Registry-v2-Verkehr erkennen und Pulls als Telemetrie erfassen (Image-/Layer-Digests, Receiver). SBOM + Advisory-Scan je gezogenem Digest. Konsole: Image-Requests, Graph (Base/Layer/Inhalt), Befunde. Noch kein Blocken.
2. **Enforcement:** Digest-basierte Allow/Deny am Gate; Freigaben/Sperren/Regeln + Karenz für Images; cosign-Verifikation.
3. **Verhalten + Betrieb:** Sandbox-Lauf des Images (URLs/Syscalls/Dateien), Re-Audit/Watch + Alerts (bereits vorhandene Loop-Infrastruktur), optionaler Admission-Controller-Export der Freigabeliste für Kubernetes.

**Offene Entscheidungen**

- Eigener Scanner-Durchlauf vs. verpflichtende Einbindung von Trivy/Grype (Lizenz-/Betriebsaufwand, Offline-Fähigkeit).
- Enforcement-Granularität: pro Image-Digest, pro Layer-Digest oder beides (Layer-Sperren treffen viele Images gleichzeitig — mächtig, aber mit Breitenwirkung).
- Umgang mit sehr großen Layern im Sandbox-/Hash-Pfad (Timeouts, Size-Caps, Streaming).
- Verhältnis zu bestehenden Registry-/Mirror-Systemen (Harbor, Artifactory, ECR Pull-Through): davor schalten vs. integrieren.
- Kubernetes-Durchsetzung: nur Freigabedaten exportieren oder einen eigenen Admission-Webhook mitliefern.
