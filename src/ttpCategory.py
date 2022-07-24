import requests
import json
import re

# MITRE Groups https://attack.mitre.org/groups/
mitre_actors = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')
mitre_actors = mitre_actors.json()

mitre_actor_list = []
for adversary in mitre_actors['objects']:
    mitre_actor_dict = {}
    if adversary['type'] == 'intrusion-set':
        mitre_actor_dict['id'] = adversary['id']
        mitre_actor_dict['name'] = adversary['name']
        created = adversary['created']
        created = created.split('T')
        mitre_actor_dict['created'] = created[0]
        last_modified = adversary['modified']
        last_modified = last_modified.split('T')
        mitre_actor_dict['last_modified'] = last_modified[0]
        mitre_actor_dict['variations'] = []
        mitre_actor_dict['variations_custom'] = []
        try:
            variations = adversary['aliases']
            for variation in variations:
                mitre_actor_dict['variations'].append(variation)
        except KeyError:
            mitre_actor_dict['variations'].append(adversary['name'])

        variations_custom = []
        for item in mitre_actor_dict['variations']:
            variation_upper = item.upper()
            variations_custom.append(variation_upper)
            if ' ' in variation_upper:
                variation_noSpace = variation_upper.replace(' ', '')
                variations_custom.append(variation_noSpace)
            if '-' in variation_upper:
                variation_noDash = variation_upper.replace('-', '')
                variations_custom.append(variation_noDash)
            try:
                if '-' in variation_noSpace:
                    variation_noSpace_noDash = variation_noSpace.replace('-', '')
                    variations_custom.append(variation_noSpace_noDash)
            except NameError:
                continue
        for i in variations_custom:
            mitre_actor_dict['variations_custom'].append(i)

        mitre_actor_list.append(mitre_actor_dict)

# Populate MITRE Group TTPs
for mitre_actor in mitre_actor_list:
    technique_list = []
    actorID = mitre_actor['id']
    ttp_patternIDs = []
    for object_relationships in mitre_actors['objects']:
        try:
            if object_relationships['source_ref'] == actorID:
                if 'attack-pattern' in object_relationships['target_ref']:
                    ttp_patternIDs.append(object_relationships['target_ref'])
        except KeyError:
            continue
    for patternID in ttp_patternIDs:
        for object_ttp in mitre_actors['objects']:
            if object_ttp['id'] == patternID:
                try:
                    for external_reference in object_ttp['external_references']:
                        try:
                            if 'CAPEC' not in external_reference['external_id']:
                                technique_list.append(external_reference['external_id'])
                        except KeyError:
                            continue
                except KeyError:
                    continue

    mitre_actor['TTPs'] = technique_list

# ETDA Actors https://apt.etda.or.th/cgi-bin/listgroups.cgi
etda_actors = requests.get('https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=g')
etda_actors = etda_actors.json()

etda_actor_list = []
for adversary in etda_actors['values']:
    etda_actor_dict = {}
    etda_actor_dict['id'] = adversary['uuid']
    name = adversary['value']
    etda_actor_dict['name'] = name
    name = name.replace('[', '')
    name = name.replace(']', '')
    name_list = re.split(', |,', name)
    etda_actor_dict['variations'] = []
    etda_actor_dict['variations_custom'] = []
    metadata = adversary['meta']
    try:
        etda_actor_dict['created'] = metadata['date']
    except KeyError:
        etda_actor_dict['created'] = 'None Provided'
    try:
        for variation in metadata['synonyms']:
            variation = variation.replace('[', '')
            variation = variation.replace(']', '')
            etda_actor_dict['variations'].append(variation)
        for name_variation in name_list:
            if name_variation not in etda_actor_dict['variations']:
                etda_actor_dict['variations'].append(name_variation)
    except KeyError:
        for name_variation in name_list:
            if name_variation not in etda_actor_dict['variations']:
                etda_actor_dict['variations'].append(name_variation)
    if 'country' in metadata.keys():
        etda_actor_dict['country'] = metadata['country']
    if 'motivation' in metadata.keys():
        etda_actor_dict['motivation'] = metadata['motivation']
    if 'cfr-target-category' in metadata.keys():
        etda_actor_dict['targeted_industries'] = metadata['cfr-target-category']
    if 'cfr-suspected-victims' in metadata.keys():
        etda_actor_dict['targeted_countries'] = metadata['cfr-suspected-victims']

    variations_custom = []
    for item in etda_actor_dict['variations']:
        variation_upper = item.upper()
        variations_custom.append(variation_upper)
        if ' ' in variation_upper:
            variation_noSpace = variation_upper.replace(' ', '')
            variations_custom.append(variation_noSpace)
        if '-' in variation_upper:
            variation_noDash = variation_upper.replace('-', '')
            variations_custom.append(variation_noDash)
        try:
            if '-' in variation_noSpace:
                variation_noSpace_noDash = variation_noSpace.replace('-', '')
                variations_custom.append(variation_noSpace_noDash)
        except NameError:
            continue
    for i in variations_custom:
        etda_actor_dict['variations_custom'].append(i)

    etda_actor_list.append(etda_actor_dict)

# Comparison
merge_list = []
id_check = []
for mitre_actor in mitre_actor_list:
    for mitre_variation in mitre_actor['variations_custom']:
        for etda_actor in etda_actor_list:
            if mitre_variation in etda_actor['variations_custom']:
                # Start compiling final data
                merge_dict = {}
                if mitre_actor['id'] in id_check:
                    continue
                else:
                    id_check.append(mitre_actor['id'])

                    merge_dict['mitre_attack_id'] = mitre_actor['id']
                    merge_dict['mitre_attack_name'] = mitre_actor['name']
                    merge_dict['mitre_attack_aliases'] = mitre_actor['variations']
                    merge_dict['mitre_attack_created'] = mitre_actor['created']
                    merge_dict['mitre_attack_last_modified'] = mitre_actor['last_modified']
                    merge_dict['etda_id'] = etda_actor['id']
                    merge_dict['etda_name'] = etda_actor['name']
                    merge_dict['etda_aliases'] = etda_actor['variations']
                    merge_dict['etda_first_seen'] = etda_actor['created']
                    if 'country' in etda_actor.keys():
                        merge_dict['country'] = etda_actor['country']
                    else:
                        merge_dict['country'] = 'None Provided'
                    if 'motivation' in etda_actor.keys():
                        merge_dict['motivation'] = etda_actor['motivation']
                    else:
                        merge_dict['motivation'] = 'None Provided'
                    if 'targeted_industries' in etda_actor.keys():
                        merge_dict['victim_industries'] = etda_actor['targeted_industries']
                    else:
                        merge_dict['victim_industries'] = 'None Provided'
                    if 'targeted_countries' in etda_actor.keys():
                        merge_dict['victim_countries'] = etda_actor['targeted_countries']
                    else:
                        merge_dict['victim_countries'] = 'None Provided'
                    merge_dict['mitre_attack_ttps'] = mitre_actor['TTPs']

                    merge_list.append(merge_dict)

outfile = open('Categorized_Adversary_TTPs.json', 'w')
json.dump(merge_list, outfile, indent=2)
