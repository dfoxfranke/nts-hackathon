from OpenSSL._util import (ffi as _ffi, lib as _lib)

#_ffi.cdef('''
#  int SSL_export_keying_material(SSL *s, unsigned char *out, size_t olen,
#                                const char *label, size_t llen,
#                                const unsigned char *context,
#                                size_t contextlen, int use_context);
#''')

def export_keying_materials(connection, out_len, label, context=None):
    out = bytearray(length)
    out_ptr = _ffi.cast("unsigned char*", _ffi.from_buffer(out))

    label_ptr = _ffi.cast("const char*", _ffi.from_buffer(label))
    label_len = len(label)

    if context is not None:
        context_ptr = _ffi.cast("const unsigned char*", _ffi.from_buffer(context))
        context_len = len(context)
        use_context = 1
    else:
        context_ptr = _ffi.cast("const unsigned char*", _ffi.NULL)
        context_len = 0
        use_context = 0

    ret = _lib.SSL_export_keying_materials(connection.ssl, out_ptr, out_len,
                                           label_ptr, label_len,
                                           context_ptr, context_len,
                                           use_context)

    if ret != 1:
        raise IOError("SSL_export_keying_materials")

    return out
