---
- name: Create the SSL Certificate
  vars:
    hostName: "{{ ansible_host }}"
  hosts: all
  gather_facts: no
  tasks:
  - name: Gather ansible_distribution fact
    setup:
      gather_subset: min
    when: ansible_distribution is not defined
  
  - name: Set facts
    set_fact:
      certName: "{{ hostName ~ '.nml.com' }}"
      certReqFile: "{{ hostName ~ '.nml.com.csr' }}"
      sslTempDir: "/nmlpkgs/informatica/software/autobuild_pkgs/pwrctr_105/sslCertRenewal"
      appliedssslDir: "/nmlpkgs/informatica/software/autobuild_pkgs/pwrctr_105/appliedCerts"
      appEnv: "{{ (ansible_host is regex('lxp.*')) | ternary('prod','test') }}"
      certTemplate: "{{ (ansible_host is not regex('lxp.*')) | ternary('NM Test Issuing CA2 SSL Code 1 - NM-SSL [Delegated Access]','NM Issuing CA2 SSL Code 1 - NM-SSL [Delegated Access]') }}" 

  - name: Clean SSL directory
    file:
      path: "{{ sslTempDir }}/"
      state: absent
  # ignore_errors: true

  - name: Create SSL directory
    file:
      path: "{{ sslTempDir }}/"
      state: directory
      group: powerctg
      mode: '0775'


  - name: Create Cert Request
    shell: |
      openssl req -new -newkey rsa:2048 -nodes -sha256 -keyout {{ hostName ~ '.nml.com.key' }} -out {{ hostName ~ '.nml.com.csr' }} -subj "/O=Northwestern Mutual/OU=ETM/L=Milwaukee/ST=WI/C=US/CN={{ hostName ~ '.nml.com' }}"
    args:
      chdir: "{{ sslTempDir }}/"
    changed_when: true
    # ignore_errors: true


  - name: Include Venafi Vault
    include_vars: vars/auth.json
    #--ask-vault-pass
  - name: Renew the SSL Certificate
    block:
      - name: Renew the SSL Certificate
        include_role:
          name: pki-renew-cert-wt
        vars:
          app_environment: test
          venafi_environment: test
          include_chain: false
          download_directory: "{{ sslTempDir }}/"
          object_name: "{{ certName }}"
          venafi_dir: "Informatica"
          csr_filename: "{{ sslTempDir }}/{{ certReqFile }}"
          cert_format: Base64
          validate_certs: false
    rescue:
    - name: Create the SSL Certificate
      include_role:
        name: pki-request-cert-wt
      vars:
        app_environment: test
        venafi_environment: test
        cert_template: "{{ certTemplate }}"
        include_chain: false
        download_directory: "{{ sslTempDir }}/"
        object_name: "{{ certName }}"
        venafi_dir: "Informatica"
        csr_filename: "{{ sslTempDir }}/{{ certReqFile }}"
        cert_format: Base64
        validate_certs: false
        
#--ask-vault-pass

#  - name: Change the Certificate cer Ownership and Permissions
#    file:
#      path: |
#         "{{ sslTempDir }}/{{ certName ~ '.cer' }}"
#      group: powerctg  
#      mode: '0775'

#  - name: Change the Certificate key Ownership and Permissions
#    file:
#      path: |
#         "{{ sslTempDir }}/{{ certName ~ '.key' }}"
#      group: powerctg  
#      mode: '0775'

#  - name: Change the Certificate csr Ownership and Permissions
#    file:
#      path: |
#         "{{ sslTempDir }}/{{ certName ~ '.csr' }}"
#      group: powerctg  
#      mode: '0775'

  # - name: Change characterset of Venafi cert
  #   command: dos2unix  "{{ sslTempDir }}/{{ hostName ~ '.nml.com.cer' }}" 
  
  - name: copy certs from temp cert path to applied cert path
    copy: 
      src: "{{ sslTempDir }}/{{ hostName ~ '.nml.com.cer' }}"
      dest: "{{ appliedssslDir }}/{{ hostName ~ '.nml.com.cer' }}"
      remote_src: yes
      owner: infautot
      group: powerctg
      mode: '0775'
    changed_when: false
    register: result
    failed_when: result.failed


  # - name: copy certs from temp cert path to applied cert path
  #   command: cp "{{ sslTempDir }}/{{ hostName ~ '.nml.com.cer' }}" "{{ appliedssslDir }}/{{ hostName ~ '.nml.com.cer' }}"
  #   changed_when: false
  #   register: result
  #   failed_when: result.failed


  - name: Set stats for next step of renewal pipeline
    set_stats:
      data:
        ssl_cutover_limit: "{{ ansible_play_hosts }}"
    run_once: true








---
- name: Create the SSL Certificate
  vars:
    hostName: "{{ ansible_host }}"
  hosts: all
  vars_files:
    - vars/sslPass.json
  gather_facts: no
  tasks:
  - name: Gather ansible_distribution fact
    setup:
      gather_subset: min
    when: ansible_distribution is not defined
  
  - name: Set facts
    set_fact:
      certName: "{{ hostName ~ '.nml.com' }}"
      certReqFile: "{{ hostName ~ '.nml.com.csr' }}"
      sslTempDir: "/nmlpkgs/informatica/software/autobuild_pkgs/pwrctr_105/sslCertRenewal"
     # sslTempDir: "/nmlpkgs/informatica/software/autobuild_pkgs/pwrctr_105/sslCertRenewal"
      appEnv: "{{ (ansible_host is regex('lxp.*')) | ternary('prod','test') }}"
      certTemplate: "{{ (ansible_host is not regex('lxp.*')) | ternary('NM Test Issuing CA2 SSL Code 1 - NM-SSL [Delegated Access]','NM Issuing CA2 SSL Code 1 - NM-SSL [Delegated Access]') }}" 


  - name: convert & import SSL cert
    shell: |
     cat {{ hostName ~ '.nml.com.cer' }} {{ hostName ~ '.nml.com.key' }} > {{ 'infa_' ~ hostName ~ '.cer' }}
     openssl pkcs12 -export -in {{ 'infa_' ~ hostName ~ '.cer' }} -out {{ 'infa_' ~  hostName ~ '.p12' }} -name "admintool" -password pass:{{ passwd }}
     keytool -v -importkeystore -srckeystore {{ 'infa_' ~ hostName ~ '.p12' }} -srcstoretype PKCS12 -destkeystore tomcat.jks -deststoretype JKS -srcalias "admintool" -destalias "admintool" -deststorepass {{ passwd }} -srcstorepass {{ passwd }}
     keytool -v -importkeystore -srckeystore {{ 'infa_' ~ hostName ~ '.p12' }} -srcstoretype PKCS12 -destkeystore infa_keystore.jks -deststoretype JKS -srcalias "admintool" -deststorepass {{ passwd }} -srcstorepass {{ passwd }} 
     keytool -import -trustcacerts -alias NMTestCAroot -file /nmlpkgs/informatica/software/autobuild_pkgs/pwrctr_105/TLSnewservers/NM_test_root.der -keystore infa_truststore.jks -storepass {{ passwd }} -noprompt
     keytool -import -trustcacerts -alias NMTestCAInt -file /nmlpkgs/informatica/software/autobuild_pkgs/pwrctr_105/TLSnewservers/NM_test_CAInt.der -keystore infa_truststore.jks -storepass {{ passwd }} -noprompt
     keytool -import -trustcacerts -alias NMTestCASSLInt -file /nmlpkgs/informatica/software/autobuild_pkgs/pwrctr_105/TLSnewservers/NM_test_SSlInt.der -keystore infa_truststore.jks -storepass {{ passwd }} -noprompt
     keytool -import -alias server -keystore infa_truststore.jks -trustcacerts -file {{ hostName ~ '.nml.com.cer' }} -storepass {{ passwd }} -noprompt
     keytool -importkeystore -srcstoretype JKS -srckeystore infa_truststore.jks -deststoretype PKCS12 -destkeystore infa_truststore.pkcs12 -deststorepass {{ passwd }} -srcstorepass {{ passwd }} -noprompt
     openssl pkcs12 -in infa_truststore.pkcs12 -nodes -out infa_truststore.pem -password pass:{{ passwd }}
     cp {{ 'infa_' ~ hostName ~ '.cer' }} infa_keystore.pem
    async: 200
    poll: 20
      
    args:
      chdir: "{{ sslTempDir }}/"
    changed_when: true

  - name: Change the Trustore Cert Ownership and Permissions
    file:
      path: "{{ sslTempDir }}/infa_truststore.pem"
      group: powerctg  
      mode: '0775'

  - name: Convert file character set from Windows to Linux
    command: dos2unix "{{ sslTempDir }}/{{ 'infa_' ~ hostName ~ '.cer' }}"

    
  - name: Add Informatica server to the inventory
    add_host:
      hostname: "{{ hostName }}"
      ansible_become_exe: /opt/seos/bin/sesu -
      ansible_become_method: su


  - name: Shutdown Informatica Services
    shell: |
     /opt/powerctr/baserel/tomcat/bin/infaservice.sh shutdown 
    args:
      chdir: "/opt/powerctr/baserel/tomcat/bin"
    become_user: infapoc
    become: true
    changed_when: true
 
  
  - name: Backup & replace certs
    shell: |
     mv infa_keystore.jks infa_keystore_$(date +%Y%m%d_%H%M%S).jks 
     mv infa_keystore.pem infa_keystore_$(date +%Y%m%d_%H%M%S).pem
     mv infa_truststore.jks infa_truststore_$(date +%Y%m%d_%H%M%S).jks
     mv infa_truststore.pem infa_truststore_$(date +%Y%m%d_%H%M%S).pem
     mv /opt/powerctr/baserel/java/bin/tomcat.jks /opt/powerctr/baserel/java/bin/tomcat_$(date +%Y%m%d_%H%M%S).jks
     cp {{ sslTempDir }}/infa_keystore.jks infa_keystore.jks
     cp {{ sslTempDir }}/infa_keystore.pem infa_keystore.pem
     cp {{ sslTempDir }}/infa_truststore.pem infa_truststore.pem
     cp {{ sslTempDir }}/infa_truststore.jks infa_truststore.jks
     cp {{ sslTempDir }}/tomcat.jks /opt/powerctr/baserel/java/bin/tomcat.jks
    args:
      chdir: "/opt/powerctr/baserel/services/shared/security/"
    become_user: infapoc
    become: true
    changed_when: true

