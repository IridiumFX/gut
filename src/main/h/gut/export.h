#ifndef GUT_EXPORT_H
#define GUT_EXPORT_H

#ifdef GUT_STATIC
    #define GUT_API
#elif defined(GUT_BUILDING)
    #ifdef _WIN32
        #define GUT_API __declspec(dllexport)
    #else
        #define GUT_API __attribute__((visibility("default")))
    #endif
#else
    #ifdef _WIN32
        #define GUT_API __declspec(dllimport)
    #else
        #define GUT_API
    #endif
#endif

#endif /* GUT_EXPORT_H */
