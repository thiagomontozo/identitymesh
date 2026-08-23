DO $$
DECLARE demo_org uuid;
BEGIN
  SELECT id INTO demo_org FROM organizations WHERE name='IdentityMesh Demo' ORDER BY created_at LIMIT 1;
  IF demo_org IS NULL THEN RAISE EXCEPTION 'IdentityMesh Demo organization missing'; END IF;
  INSERT INTO identity_connectors(id,organization_id,name,type,base_url,environment,write_enabled,capabilities,last_sync_status)
  VALUES
    ('10000000-0000-4000-8000-000000000001',demo_org,'SCIM Cloud App A','SCIM_2_0','http://mock-scim-a:8090/scim/v2','TEST',true,'["DISCOVER_USERS","DISCOVER_GROUPS","DISABLE_ACCOUNT"]','SUCCEEDED'),
    ('10000000-0000-4000-8000-000000000002',demo_org,'SCIM Cloud App B','SCIM_2_0','http://mock-scim-b:8090/scim/v2','TEST',true,'["DISCOVER_USERS","DISCOVER_GROUPS","DISABLE_ACCOUNT"]','SUCCEEDED'),
    ('10000000-0000-4000-8000-000000000003',demo_org,'Corporate LDAP','LDAP_DIRECTORY','ldap://openldap-test:389','TEST',false,'["DISCOVER_USERS","DISCOVER_GROUPS","DISCOVER_MEMBERSHIPS"]','SUCCEEDED'),
    ('10000000-0000-4000-8000-000000000004',demo_org,'CSV Authoritative Source','CSV_AUTHORITATIVE_SOURCE',NULL,'TEST',false,'["DISCOVER_USERS"]','SUCCEEDED')
  ON CONFLICT(id) DO NOTHING;
  INSERT INTO people(id,organization_id,authoritative_source_id,external_person_id,display_name,primary_email,employee_number,department,lifecycle_status)
  VALUES
    ('20000000-0000-4000-8000-000000000001',demo_org,'10000000-0000-4000-8000-000000000004','E1001','Alex Morgan','alex.morgan@identitymesh.test','E1001','Engineering','TERMINATED'),
    ('20000000-0000-4000-8000-000000000002',demo_org,'10000000-0000-4000-8000-000000000004','E1002','Jordan Lee','jordan.lee@identitymesh.test','E1002','Security','ACTIVE'),
    ('20000000-0000-4000-8000-000000000003',demo_org,'10000000-0000-4000-8000-000000000004','E1003','Taylor Silva','taylor.silva@identitymesh.test','E1003','Finance','ACTIVE'),
    ('20000000-0000-4000-8000-000000000004',demo_org,'10000000-0000-4000-8000-000000000004','E1004','Morgan Chen','morgan.chen@identitymesh.test','E1004','Operations','LEAVE'),
    ('20000000-0000-4000-8000-000000000005',demo_org,'10000000-0000-4000-8000-000000000004','E1005','Sam Rivera','sam.rivera@identitymesh.test','E1005','Engineering','ACTIVE')
  ON CONFLICT(id) DO NOTHING;
  INSERT INTO identity_accounts(id,organization_id,connector_id,external_account_id,username,display_name,primary_email,employee_number,active_status,account_type)
  VALUES
    ('30000000-0000-4000-8000-000000000001',demo_org,'10000000-0000-4000-8000-000000000001','alex-a','alex.morgan','Alex Morgan','alex.morgan@identitymesh.test','E1001','ACTIVE','HUMAN'),
    ('30000000-0000-4000-8000-000000000002',demo_org,'10000000-0000-4000-8000-000000000002','alex-a','alex.morgan','Alex Morgan','alex.morgan@identitymesh.test','E1001','ACTIVE','HUMAN'),
    ('30000000-0000-4000-8000-000000000003',demo_org,'10000000-0000-4000-8000-000000000003','uid=alex.morgan,ou=people,dc=identitymesh,dc=test','alex.morgan','Alex Morgan','alex.morgan@identitymesh.test','E1001','DISABLED','HUMAN'),
    ('30000000-0000-4000-8000-000000000004',demo_org,'10000000-0000-4000-8000-000000000001','orphan-legacy','legacy.contractor','Legacy Contractor','legacy.contractor@external.test',NULL,'ACTIVE','UNKNOWN'),
    ('30000000-0000-4000-8000-000000000005',demo_org,'10000000-0000-4000-8000-000000000001','ambiguous','taylor.other','Taylor Silva','someone.else@external.test',NULL,'ACTIVE','UNKNOWN')
  ON CONFLICT(id) DO NOTHING;
  INSERT INTO identity_links(organization_id,person_id,identity_account_id,link_type,confidence,reason)
  VALUES
    (demo_org,'20000000-0000-4000-8000-000000000001','30000000-0000-4000-8000-000000000001','AUTOMATIC','HIGH','exact immutable employee identifier'),
    (demo_org,'20000000-0000-4000-8000-000000000001','30000000-0000-4000-8000-000000000002','AUTOMATIC','HIGH','exact immutable employee identifier'),
    (demo_org,'20000000-0000-4000-8000-000000000001','30000000-0000-4000-8000-000000000003','AUTOMATIC','HIGH','exact immutable employee identifier')
  ON CONFLICT(organization_id,identity_account_id) DO NOTHING;
  INSERT INTO correlation_candidates(organization_id,person_id,identity_account_id,confidence,reasons)
  VALUES(demo_org,'20000000-0000-4000-8000-000000000003','30000000-0000-4000-8000-000000000005','LOW','["name-only similarity is never auto-linked"]')
  ON CONFLICT DO NOTHING;
  INSERT INTO identity_findings(organization_id,identity_account_id,connector_id,type,severity,reason)
  SELECT demo_org,'30000000-0000-4000-8000-000000000004','10000000-0000-4000-8000-000000000001','ORPHAN_ACCOUNT','ATTENTION','Observed account has no linked person'
  WHERE NOT EXISTS(SELECT 1 FROM identity_findings WHERE organization_id=demo_org AND identity_account_id='30000000-0000-4000-8000-000000000004' AND type='ORPHAN_ACCOUNT');
END $$;
