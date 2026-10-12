// Minimal CPython 2.3 ABI, matching the symbols the engine's dice_py exports and that the shipped
// bf2hub.dll imports (dumpbin /IMPORTS bf2hub.dll -> dice_py.dll). We declare only what the
// `bf2hublib` module touches. Everything here must stay layout- and calling-convention-compatible
// with dice_py; it is an ABI contract, not our own type system.
//
// dice_py is the embedded CPython 2.3.4. Objects we create are reference-counted and freed by the
// interpreter, so PyObject must match 2.3 exactly: ob_refcnt is a plain C `int` in 2.3 (Py_ssize_t
// did not arrive until 2.5), and tp_dealloc sits at offset 24/48 (x86/x64) in the type object - the
// slot the shipped code dereferences when it inlines Py_DECREF.

#ifndef BF2HUB_PYABI_H
#define BF2HUB_PYABI_H

#include <cstddef>

extern "C" {

struct PyObject;
struct PyTypeObject;

typedef void (*destructor)(PyObject*);

// PyObject (2.3 layout). We only need the head for refcount handling and type checks.
struct PyObject {
    int           ob_refcnt;
    PyTypeObject* ob_type;
};

// The 2.3 PyTypeObject begins with PyObject_VAR_HEAD (ob_refcnt, ob_type, ob_size) then
// tp_name/tp_basicsize/tp_itemsize/tp_dealloc. We lay out exactly that prefix so tp_dealloc lands at
// offset 24 (x86) / 48 (x64) - the slot the shipped code dereferences when it inlines Py_DECREF.
struct PyTypeObject {
    int           ob_refcnt;
    PyTypeObject* ob_type;
    long          ob_size;
    const char*   tp_name;
    long          tp_basicsize;
    long          tp_itemsize;
    destructor    tp_dealloc;
};

typedef PyObject* (*PyCFunction)(PyObject*, PyObject*);

struct PyMethodDef {
    const char* ml_name;
    PyCFunction ml_meth;
    int         ml_flags;
    const char* ml_doc;
};

// Method flags (2.3).
#define BF2HUB_METH_VARARGS  0x0001
#define BF2HUB_METH_KEYWORDS 0x0002
#define BF2HUB_METH_NOARGS   0x0004

// 2.3 module API version. Py_InitModule4 rejects a mismatch, so this must be exactly 1012.
#define BF2HUB_PYTHON_API_VERSION 1012

// dice_py is a DLL, so its DATA exports must be referenced through __declspec(dllimport); without it
// the linker looks for the raw symbol instead of the __imp_ thunk and fails. (Functions resolve via
// the import library's thunks either way, but marking them import is harmless and conventional.)
#if defined(_WIN32)
#  define BF2HUB_PYDATA __declspec(dllimport)
#else
#  define BF2HUB_PYDATA extern
#endif

// Imported singletons (data exports). Py_None etc. are &_Py_NoneStruct in CPython.
BF2HUB_PYDATA PyObject _Py_NoneStruct;
BF2HUB_PYDATA PyObject _Py_TrueStruct;
BF2HUB_PYDATA PyObject _Py_ZeroStruct;   // the int 0 singleton
BF2HUB_PYDATA PyTypeObject PyString_Type;
BF2HUB_PYDATA PyTypeObject PyModule_Type;

// Imported exception type objects (each is a PyObject*).
BF2HUB_PYDATA PyObject* PyExc_RuntimeError;
BF2HUB_PYDATA PyObject* PyExc_ValueError;
BF2HUB_PYDATA PyObject* PyExc_TypeError;
BF2HUB_PYDATA PyObject* PyExc_IndexError;

// Imported functions.
int        PyArg_ParseTuple(PyObject* args, const char* format, ...);
PyObject*  PyErr_Format(PyObject* exception, const char* format, ...);
PyObject*  PyString_FromString(const char* v);
PyObject*  PyString_FromFormat(const char* format, ...);
char*      PyString_AsString(PyObject* string);
PyObject*  PyLong_FromLong(long v);
PyObject*  PyObject_CallMethod(PyObject* o, const char* method, const char* format, ...);
int        PyType_IsSubtype(PyTypeObject* a, PyTypeObject* b);

// Module registration / import. Our IAT hook captures the engine's resolved addresses of these and
// calls through to them; the declarations let us form the right call.
PyObject*  Py_InitModule4(const char* name, PyMethodDef* methods, const char* doc,
                          PyObject* self, int apiver);
PyObject*  PyImport_ImportModule(const char* name);

} // extern "C"

// Convenience, matching the 2.3 macros the shipped code inlines.
#define BF2HUB_Py_None   (&_Py_NoneStruct)
#define BF2HUB_Py_True   (&_Py_TrueStruct)
#define BF2HUB_Py_Zero   (&_Py_ZeroStruct)

static inline PyObject* bf2hub_Py_INCREF(PyObject* o) { if (o) ++o->ob_refcnt; return o; }
static inline void      bf2hub_Py_DECREF(PyObject* o) {
    if (o && --o->ob_refcnt == 0 && o->ob_type && o->ob_type->tp_dealloc)
        o->ob_type->tp_dealloc(o);
}
// Return a new reference to Py_None (the common success return).
static inline PyObject* bf2hub_ReturnNone() { return bf2hub_Py_INCREF(BF2HUB_Py_None); }

#endif // BF2HUB_PYABI_H
