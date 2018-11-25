#include <Arme/MsgHandler.h>
#include <stdio.h>
#include <stdarg.h>

#include <string>

bool MsgAlert(bool yes_no, int Style, const char* format, ...)
{
    va_list list;
    va_start(list, format);

    std::string res;
    res.resize(512);
    vsnprintf(&res[0], 512, format, list);

    throw std::exception(res.data());

    return true;
}