# Categorized Adversary TTPs

## MITRE ATT&CK x ThaiCERT = new pivot opportunities for TTP analysis & threat modeling

This is a (work in progress) partial merge of two powerful cyber adversary datasets, to capitalize on each one's strengths: [MITRE ATT&CK](https://attack.mitre.org/) and its **Group-to-TTP linkages**; and [ETDA/ThaiCERT](https://apt.etda.or.th/cgi-bin/aptgroups.cgi)'s Threat Group Cards and their **structured "metadata" fields**, containing supporting details about real-world cyber threat activity, such as victim industry & country and suspected attacker country & motivation.

Anecdotally, ThaiCERT's repository is less well-known yet it contains a wealth of useful - and importantly, structured, cyber threat event metadata. Among many other data points, the repository contains **400+ named adversary groups** and event metadata covering:

* **41 industry sectors**
* **149 victim countries**
* **16 attacker countries**
* **4 attacker motivation categories**: Sabotage and destruction, Information theft and espionage, Financial gain (generally), and Financial crime (specifically)

MITRE ATT&CK's popular knowledge base contains profiles on **130+ actor groups**. A key value of ATT&CK's dataset is its links between groups and their associated identified Tactics, Techniques, & Procedures, based on use observed in publicly reported threat activity. Tactics, Techniques & Sub-Techniques have unique identifiers allowing teams across the community to use a common language to refer back to the same TTPs.

The merge of the adversary datasets is based on a quick matching algorithm involving small twists on the very many actor names and variations in each source. The script used to generate the dataset is available [here](https://github.com/tropChaud/Categorized-Adversary-TTPs/blob/main/app/ttpCategory.py) and structured for continuous updates to the dataset over time.

### A key anticipated use case for this repository is to support faster development of inputs to an organization's cyber threat model/profile.
![threatModel](https://raw.githubusercontent.com/tropChaud/Categorized-Adversary-TTPs/main/docs/ttpCategories_transparent.png)
Dropping these inputs into [Control Validation Compass](https://controlcompass.github.io/risk) enables further fast pivoting to relevant controls & validation tests aligned with each relevant top-priority TTP.

The rough merge of the datasets enables easier analysis along the following lines:

* What is the distribution of TTPs used against a given industry, and/or how does that compare to other industries? For example:

**Aerospace Industry TTPs ([data](https://github.com/tropChaud/Categorized-Adversary-TTPs/blob/main/docs/heatmaps/industries/Aerospace.json), [live visualization](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FtropChaud%2FCategorized-Adversary-TTPs%2Fmain%2Fdocs%2Fheatmaps%2Findustries%2FAerospace.json))**

![aerospaceTTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs/blob/main/docs/heatmaps/industries/Aerospace.png)

**Pharmaceutical Industry TTPs ([data](https://github.com/tropChaud/Categorized-Adversary-TTPs/blob/main/docs/heatmaps/industries/Pharmaceutical.json), [live visualization](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FtropChaud%2FCategorized-Adversary-TTPs%2Fmain%2Fdocs%2Fheatmaps%2Findustries%2FPharmaceutical.json))**

![pharmaceuticalTTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs/blob/main/docs/heatmaps/industries/Pharmaceutical.png)

* What is the distribution of TTPs used by certain types of adversaries, based on their motivations, and/or how does that compare to other types of adversaries? For example:

**"Information theft and espionage" Adversary TTPs ([data](https://github.com/tropChaud/Categorized-Adversary-TTPs/blob/main/docs/heatmaps/motivations/Information%20theft%20and%20espionage.json), [live visualization](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FtropChaud%2FCategorized-Adversary-TTPs%2Fmain%2Fdocs%2Fheatmaps%2Fmotivations%2FInformation%20theft%20and%20espionage.json))**

![espionageTTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs/blob/main/docs/heatmaps/motivations/Information_theft_and_espionage.png)

**"Financial crime" Adversary TTPs ([data](https://github.com/tropChaud/Categorized-Adversary-TTPs/blob/main/docs/heatmaps/motivations/Financial%20crime.json), [live visualization](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FtropChaud%2FCategorized-Adversary-TTPs%2Fmain%2Fdocs%2Fheatmaps%2Fmotivations%2FFinancial%20crime.json))**

![criminalTTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs/blob/main/docs/heatmaps/motivations/Financial_crime.png)

# Using Categorized Adversary TTPs

Details and examples for using the data files in this repository are continuing to be build and live in the [<code>heatmaps</code>](https://github.com/tropChaud/Categorized-Adversary-TTPs/tree/main/docs/heatmaps) and [<code>csv_for_pivot_tables</code>](https://github.com/tropChaud/Categorized-Adversary-TTPs/tree/main/docs/csv_for_pivot_tables) folders.

## Acknowledgements
Immense thanks to the supporting teams and independent contributors to MITRE ATT&CK, and to Martijn van der Heide, the rest of ThaiCERT, and contributing CERT teams and security researchers supporting the Threat Group Cards project. Thank you for continuing to maintain and make publicly available these critical security resources.

MITRE ATT&CK® is a registered trademark of The MITRE Corporation

Threat Group Cards: A Threat Actor Encyclopedia is a Copyright © Electronic Transactions Development Agency, 2019-2022
