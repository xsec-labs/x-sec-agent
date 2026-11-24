# 漏洞 Skill 路由索引

由 `python3 scripts/build_routing_index.py` 从 `config/vulnerability-skills.yaml` 生成，不要手改。
一行一个 Skill，观察到任一信号即可考虑派发；多个同时命中按本表顺序（`priority` 从高到低）。
信号只是候选条件，派发前还要看该条目的 `requires_environment`、`requires_artifacts`、`blocked_when`。
格式：`信号 / 信号 → Skill id [阶段] 目录名`；路径是 `skills/<目录名>`，目录名与 id 或 `xsec-<id>` 相同时省略。

- login_form_detected / password_field_detected / auth_endpoint_detected / admin_login_form_detected / dirsearch_login_route_detected → weak-pass-check [pre_auth]
- login_form_detected / auth_endpoint_detected / known_username_available / weak_pass_check_completed / late_auth_testing_phase → account-enumeration [late_pre_auth_or_finish] xsec-account-enumeration-leakage
- login_form_detected / auth_endpoint_detected / failed_login_baseline_available / captcha_absent_on_auth / password_spray_surface_detected → brute-force-protection [pre_auth]
- captcha_detected / otp_endpoint_detected / sms_send_endpoint_detected / email_send_endpoint_detected / notification_send_endpoint_detected / password_reset_flow_detected → captcha-otp-defect [pre_auth_or_post_auth]
- api_doc_route_detected / swagger_route_detected / openapi_spec_detected / knife4j_route_detected / wsdl_route_detected / api_dirsearch_endpoint_detected → api-interface-exposure [recon_or_any]
- source_map_detected / js_secret_candidate_detected / frontend_route_inventory_detected / client_config_detected / mobile_package_available / passive_secret_match → client-hardcoded-secret [recon_or_any]
- passive_secret_match / passive_private_key_match / js_secret_candidate_detected / config_secret_candidate_detected / object_storage_credential_detected → cloud-secret-leakage [any]
- passive_object_storage_bucket_detected / object_storage_bucket_detected / object_storage_listing_detected / object_storage_upload_allowed / object_storage_acl_policy_exposed / bucket_takeover_candidate → object-storage-bucket [any]
- config_path_detected / backup_path_detected / env_file_detected / vcs_directory_detected / archive_file_detected / db_backup_detected → config-backup-leakage [recon_or_any]
- directory_listing_detected / dirsearch_sensitive_path_detected / static_directory_exposed / object_storage_listing_detected / backup_path_detected → directory-sensitive-leakage [recon_or_any]
- management_console_detected / actuator_route_detected / nacos_route_detected / admin_route_detected / monitoring_endpoint_detected / config_center_route_detected → middleware-unauth-management [recon_or_any]
- passive_shiro_cookie_detected → shiro-attack-detection [passive_review_or_any]
- frontend_endpoint_path_candidate_detected / frontend_route_inventory_detected / api_base_path_detected / public_protected_route_detected / admin_route_unauth_accessible / api_unauth_candidate_detected / protected_resource_returns_200_without_session / dirsearch_sensitive_path_detected → unauth-access [pre_auth_or_post_auth]
- server_header_version_detected / x_powered_by_detected / framework_version_detected / default_page_detected / debug_page_detected / component_version_detected → version-info-exposure [recon_or_any]
- http_scheme_detected / login_over_http_detected / sensitive_api_over_http_detected / tls_weakness_detected / mixed_content_detected / secure_cookie_missing → transport-security [recon_or_any] xsec-transport-security-plaintext-tls
- set_cookie_observed / session_cookie_detected / auth_cookie_detected / remember_me_detected / sso_callback_detected → cookie-security-flags [pre_auth_or_post_auth]
- cors_header_observed / origin_reflection_detected / acao_wildcard_detected / acac_true_detected / sensitive_api_fields_detected → cors-misconfiguration [api_or_post_auth]
- passive_sql_error_match / server_error_with_sql_keyword / database_error_page_detected / orm_error_detected / sql_statement_fragment_detected → sql-error-info-leak [any]
- passive_detailed_error_match / passive_path_leak_match / server_error_with_stack_trace / absolute_path_detected / debug_error_page_detected → error-path-leakage [any]
- passive_internal_ip_match / passive_internal_hostname_match / internal_port_detected / upstream_host_leak_detected / client_internal_url_detected → internal-network-leakage [any]
- parameterized_request_detected / search_or_filter_form_detected / sort_or_page_param_detected / sqli_hook_candidate / passive_sql_error_match / sql_injection_candidate → sql-injection [api_or_post_auth]
- reflected_input_detected / stored_input_surface_detected / rich_text_editor_detected / dom_sink_detected / unsafe_html_render_detected / ai_output_rendered_in_frontend / file_upload_name_reflected → xss [surface_or_post_auth] xsec-xss-methodology-42
- url_fetch_parameter_detected / webhook_url_field_detected / remote_image_import_detected / callback_url_detected / ssrf_candidate_detected / file_preview_remote_url_detected → ssrf [surface_or_post_auth] xsec-ssrf-methodology
- path_parameter_detected / filename_parameter_detected / file_download_endpoint_detected / file_preview_endpoint_detected / static_file_route_detected / traversal_error_hint_detected → path-traversal [surface_or_post_auth]
- file_download_endpoint_detected / file_preview_endpoint_detected / attachment_id_detected / signed_download_url_detected / export_endpoint_detected / id_like_resource_paths_detected → file-download-access-control [post_auth_or_surface]
- file_upload_form_detected / file_upload_api_detected / object_storage_upload_credential_detected / rich_text_upload_detected / import_endpoint_detected → file-upload-security [post_auth_or_surface]
- llm_chat_interface_detected / model_stream_endpoint_detected / rag_endpoint_detected / prompt_template_leak_candidate / ai_output_rendered_in_frontend → llm-prompt-security [surface_or_post_auth]
- authenticated_session_obtained / remember_me_detected / browser_storage_token_detected / jwt_token_detected / password_value_in_storage_detected → browser-sensitive-storage [post_auth]
- jwt_token_detected / bearer_token_detected / authenticated_session_obtained / authorization_header_observed / storage_token_detected → jwt-security [post_auth_or_token]
- authenticated_session_obtained / logout_flow_detected / password_change_flow_detected / refresh_token_detected / remember_me_detected / jwt_token_detected → session-token-invalidation [post_auth]
- authenticated_session_obtained / role_switch_available / second_account_available / id_like_resource_paths_detected / 403_or_401_boundary_observed / customer_data_fields_detected → access-control-idor [post_auth]
- password_change_flow_detected / password_reset_flow_detected / registration_form_detected / admin_user_create_detected / first_login_password_change_detected / weak_password_set_attempt_allowed → password-policy [post_auth]
- password_value_in_request_detected / password_value_in_response_detected / password_value_in_storage_detected / remember_password_detected / reset_password_returns_plaintext → password-storage-return [post_auth_or_auth_flow]
- encoded_sensitive_value_detected / client_crypto_code_detected / hardcoded_crypto_key_detected / weak_algorithm_detected / fixed_iv_detected / jwt_weak_algorithm_detected → insecure-crypto [any]
- state_changing_form_detected / state_changing_api_detected / cookie_auth_state_changing_endpoint / csrf_token_missing / samesite_none_or_lax_observed → csrf-protection-missing [post_auth]

收尾处理器（不在启动阶段默认运行）：
- passive_findings_available → passive-sensitive-review [passive_review] xsec-passive-scanning
- source_code_leakage_candidate → code-audit-bridge [any]
- multiple_validated_issues / issue_plus_key_win / credential_to_session_chain_candidate / passive_secret_plus_api_exposure → vulnerability-chain-analysis [chain_analysis]
