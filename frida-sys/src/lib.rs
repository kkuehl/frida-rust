/*
 * Copyright © 2020-2022 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[allow(clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::*;

#[cfg(not(any(target_vendor = "apple", target_os = "windows")))]
pub use crate::{
    _frida_g_bytes_get_data as g_bytes_get_data, _frida_g_bytes_new as g_bytes_new,
    _frida_g_bytes_unref as g_bytes_unref, _frida_g_clear_object as g_clear_object,
    _frida_g_error_free as g_error_free, _frida_g_free as g_free,
    _frida_g_hash_table_insert as g_hash_table_insert,
    _frida_g_hash_table_iter_init as g_hash_table_iter_init,
    _frida_g_hash_table_iter_next as g_hash_table_iter_next,
    _frida_g_hash_table_new_full as g_hash_table_new_full,
    _frida_g_hash_table_size as g_hash_table_size, _frida_g_hash_table_unref as g_hash_table_unref,
    _frida_g_idle_source_new as g_idle_source_new, _frida_g_object_ref as g_object_ref,
    _frida_g_signal_connect_data as g_signal_connect_data,
    _frida_g_signal_handler_disconnect as g_signal_handler_disconnect,
    _frida_g_source_attach as g_source_attach,
    _frida_g_source_set_callback as g_source_set_callback, _frida_g_source_unref as g_source_unref,
    _frida_g_str_equal as g_str_equal, _frida_g_str_hash as g_str_hash,
    _frida_g_strdup as g_strdup, _frida_g_strfreev as g_strfreev,
    _frida_g_string_free as g_string_free, _frida_g_string_free_to_bytes as g_string_free_to_bytes,
    _frida_g_variant_get_boolean as g_variant_get_boolean,
    _frida_g_variant_get_byte as g_variant_get_byte,
    _frida_g_variant_get_double as g_variant_get_double,
    _frida_g_variant_get_int16 as g_variant_get_int16,
    _frida_g_variant_get_int32 as g_variant_get_int32,
    _frida_g_variant_get_int64 as g_variant_get_int64,
    _frida_g_variant_get_string as g_variant_get_string,
    _frida_g_variant_get_type_string as g_variant_get_type_string,
    _frida_g_variant_get_uint16 as g_variant_get_uint16,
    _frida_g_variant_get_uint32 as g_variant_get_uint32,
    _frida_g_variant_get_uint64 as g_variant_get_uint64,
    _frida_g_variant_iter_init as g_variant_iter_init,
    _frida_g_variant_iter_loop as g_variant_iter_loop,
    _frida_g_variant_new_boolean as g_variant_new_boolean,
    _frida_g_variant_new_int64 as g_variant_new_int64,
    _frida_g_variant_new_string as g_variant_new_string,
    _frida_g_variant_ref_sink as g_variant_ref_sink, _frida_g_variant_unref as g_variant_unref,
};

// What the generated `frida::gir` layer of the `frida` crate calls besides the above.
#[cfg(not(any(target_vendor = "apple", target_os = "windows")))]
pub use crate::{
    _frida_g_cancellable_cancel as g_cancellable_cancel,
    _frida_g_cancellable_get_type as g_cancellable_get_type,
    _frida_g_cancellable_is_cancelled as g_cancellable_is_cancelled,
    _frida_g_cancellable_new as g_cancellable_new, _frida_g_file_get_path as g_file_get_path,
    _frida_g_file_get_type as g_file_get_type, _frida_g_file_new_for_path as g_file_new_for_path,
    _frida_g_io_stream_get_type as g_io_stream_get_type,
    _frida_g_object_get_type as g_object_get_type, _frida_g_quark_to_string as g_quark_to_string,
    _frida_g_tls_certificate_get_type as g_tls_certificate_get_type,
    _frida_g_tls_certificate_new_from_pem as g_tls_certificate_new_from_pem,
    _frida_g_type_check_instance_is_a as g_type_check_instance_is_a,
    _frida_g_type_name as g_type_name, _frida_g_variant_new_array as g_variant_new_array,
    _frida_g_variant_new_dict_entry as g_variant_new_dict_entry,
    _frida_g_variant_new_strv as g_variant_new_strv,
    _frida_g_variant_new_variant as g_variant_new_variant,
    _frida_g_variant_type_free as g_variant_type_free,
    _frida_g_variant_type_new as g_variant_type_new,
};

// What `frida::gir`'s signals, RPC and Gio handles call besides the above.
#[cfg(not(any(target_vendor = "apple", target_os = "windows")))]
pub use crate::{
    _frida_g_cancellable_connect as g_cancellable_connect,
    _frida_g_cancellable_disconnect as g_cancellable_disconnect,
    _frida_g_main_context_is_owner as g_main_context_is_owner,
    _frida_g_object_get_data as g_object_get_data,
    _frida_g_object_set_data_full as g_object_set_data_full,
    _frida_g_signal_handler_is_connected as g_signal_handler_is_connected,
    _frida_g_socket_address_get_type as g_socket_address_get_type,
    _frida_g_socket_connectable_to_string as g_socket_connectable_to_string,
    _frida_g_weak_ref_clear as g_weak_ref_clear, _frida_g_weak_ref_get as g_weak_ref_get,
    _frida_g_weak_ref_init as g_weak_ref_init,
};
