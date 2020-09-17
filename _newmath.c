//_newmath.c
// Include standard libraries
#include <Python.h>
#include <string.h>
#include <stdio.h>
#include "libnewmath.h"

static PyObject *sum_wrapper(PyObject *self, PyObject *args) {
    char *p_priv_data;
    char *p_udid;  // 手机令牌序列号
    char *p_ap;  // 手机令牌PIN


    if (!PyArg_ParseTuple(args, "sss", &p_priv_data, &p_udid, &p_ap))
{
    PyErr_SetString(PyExc_TypeError, "Oh no!");
    PyErr_Print();
        return NULL;
}
    printf("Length of string a = %zu \n",strlen(p_priv_data));

    GoString a = {p_priv_data, strlen(p_priv_data)} ;
    GoString b = {p_udid, strlen(p_udid)} ;
    GoString c = {p_ap, strlen(p_ap)} ;

    return PyLong_FromLong(sum(a, b, c));
}

static PyMethodDef MathMethods[] = {
    {"sum_qqq", sum_wrapper, METH_VARARGS, "Add two numbers."},
    {NULL, NULL, 0, NULL}
};



// PyInit Module
PyMODINIT_FUNC initnewmath(void) {
    Py_InitModule3("newmath", MathMethods, "xxx");
}


//vi:ts=4:et
//-*- EOF -*-

