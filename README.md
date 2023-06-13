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
