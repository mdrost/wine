/* Wine Vulkan ICD implementation
 *
 * Copyright 2017 Roderick Colenbrander
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winuser.h"

#include "wine/debug.h"
#include "wine/heap.h"
#include "wine/vulkan.h"
#include "wine/vulkan_driver.h"
#include "vulkan_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(vulkan);

/* For now default to 4 as it felt like a reasonable version feature wise to support.
 * Don't support the optional vk_icdGetPhysicalDeviceProcAddr introduced in this version
 * as it is unlikely we will implement physical device extensions, which the loader is not
 * aware off. Version 5 adds more extensive version checks. Something to tackle later.
 */
#define WINE_VULKAN_ICD_VERSION 4

/* All Vulkan structures use this structure for the first elements. */
struct wine_vk_structure_header
{
    VkStructureType sType;
    const void *pNext;
};

static void *wine_vk_get_global_proc_addr(const char *name);

static const struct vulkan_funcs *vk_funcs = NULL;

/* Helper function used for freeing a device structure. This function supports full
 * and partial object cleanups and can thus be used for vkCreateDevice failures.
 */
static void wine_vk_device_free(struct VkDevice_T *device)
{
    if (!device)
        return;

    if (device->device && device->funcs.p_vkDestroyDevice)
    {
        device->funcs.p_vkDestroyDevice(device->device, NULL /* pAllocator */);
    }

    heap_free(device);
}

static BOOL wine_vk_init(void)
{
    HDC hdc = GetDC(0);

    vk_funcs =  __wine_get_vulkan_driver(hdc, WINE_VULKAN_DRIVER_VERSION);
    if (!vk_funcs)
    {
        ERR("Failed to load Wine graphics driver supporting Vulkan.\n");
        ReleaseDC(0, hdc);
        return FALSE;
    }

    ReleaseDC(0, hdc);
    return TRUE;
}

/* Helper function for converting between win32 and host compatible VkInstanceCreateInfo.
 * This function takes care of extensions handled at winevulkan layer, a Wine graphics
 * driver is responsible for handling e.g. surface extensions.
 */
static VkResult wine_vk_instance_convert_create_info(const VkInstanceCreateInfo *src,
        VkInstanceCreateInfo *dst)
{
    dst->sType = src->sType;
    dst->flags = src->flags;
    dst->pApplicationInfo = src->pApplicationInfo;

    /* Application and loader can pass in a chain of extensions through pNext.
     * We can't blindy pass these through as often these contain callbacks or
     * they can even be pass structures for loader / ICD internal use. For now
     * we ignore everything in pNext chain, but we print FIXMEs.
     */
    if (src->pNext)
    {
        const struct wine_vk_structure_header *header;

        for (header = src->pNext; header; header = header->pNext)
        {
            switch (header->sType)
            {
                case VK_STRUCTURE_TYPE_LOADER_INSTANCE_CREATE_INFO:
                    /* Can be used to register new dispatchable object types
                     * to the loader. We should ignore it as it will confuse the
                     * host its loader.
                     */
                    break;

                default:
                    FIXME("Application requested a linked structure of type %d\n", header->sType);
            }
        }
    }
    /* For now don't support anything. */
    dst->pNext = NULL;

    /* ICDs don't support any layers, so nothing to copy. Modern versions of the loader
     * filter this data out as well.
     */
    dst->enabledLayerCount = 0;
    dst->ppEnabledLayerNames = NULL;

    /* TODO: convert non-WSI win32 extensions here to host specific ones. */
    dst->ppEnabledExtensionNames = src->ppEnabledExtensionNames;
    dst->enabledExtensionCount = src->enabledExtensionCount;

    return VK_SUCCESS;
}

/* Helper function which stores wrapped physical devices in the instance object. */
static VkResult wine_vk_instance_load_physical_devices(struct VkInstance_T *instance)
{
    VkResult res;
    struct VkPhysicalDevice_T **tmp_phys_devs = NULL;
    uint32_t num_phys_devs = 0;
    unsigned int i;

    res = instance->funcs.p_vkEnumeratePhysicalDevices(instance->instance, &num_phys_devs, NULL);
    if (res != VK_SUCCESS)
    {
        ERR("Failed to enumerate physical devices, res=%d\n", res);
        return res;
    }

    /* Don't bother with any of the rest if the system just lacks devices. */
    if (num_phys_devs == 0)
        return VK_SUCCESS;

    tmp_phys_devs = heap_calloc(num_phys_devs, sizeof(*tmp_phys_devs));
    if (!tmp_phys_devs)
        return VK_ERROR_OUT_OF_HOST_MEMORY;

    res = instance->funcs.p_vkEnumeratePhysicalDevices(instance->instance, &num_phys_devs, tmp_phys_devs);
    if (res != VK_SUCCESS)
        goto err;

    instance->phys_devs = heap_calloc(num_phys_devs, sizeof(*instance->phys_devs));
    if (!instance->phys_devs)
    {
        res = VK_ERROR_OUT_OF_HOST_MEMORY;
        goto err;
    }

    /* Wrap each native physical device handle into a dispatchable object for the ICD loader. */
    for (i = 0; i < num_phys_devs; i++)
    {
        struct VkPhysicalDevice_T *phys_dev = heap_alloc(sizeof(*phys_dev));
        if (!phys_dev)
        {
            ERR("Unable to allocate memory for physical device!\n");
            res = VK_ERROR_OUT_OF_HOST_MEMORY;
            goto err;
        }

        phys_dev->base.loader_magic = VULKAN_ICD_MAGIC_VALUE;
        phys_dev->instance = instance;
        phys_dev->phys_dev = tmp_phys_devs[i];

        instance->phys_devs[i] = phys_dev;
        instance->num_phys_devs = i + 1;
    }
    instance->num_phys_devs = num_phys_devs;

    heap_free(tmp_phys_devs);
    return VK_SUCCESS;

err:
    heap_free(tmp_phys_devs);

    return res;
}

/* Helper function used for freeing an instance structure. This function supports full
 * and partial object cleanups and can thus be used for vkCreateInstance failures.
 */
static void wine_vk_instance_free(struct VkInstance_T *instance)
{
    if (!instance)
        return;

    if (instance->phys_devs)
    {
        unsigned int i;

        for (i = 0; i < instance->num_phys_devs; i++)
        {
            heap_free(&instance->phys_devs[i]);
        }
        heap_free(instance->phys_devs);
    }

    if (instance->instance)
        vk_funcs->p_vkDestroyInstance(instance->instance, NULL /* allocator */);

    heap_free(instance);
}

VkResult WINAPI wine_vkAcquireNextImageKHR(VkDevice device, VkSwapchainKHR swapchain,
        uint64_t timeout, VkSemaphore semaphore, VkFence fence, uint32_t *image_index)
{
    TRACE("%p, 0x%s, 0x%s, 0x%s, 0x%s, %p\n", device, wine_dbgstr_longlong(swapchain),
            wine_dbgstr_longlong(timeout), wine_dbgstr_longlong(semaphore),
            wine_dbgstr_longlong(fence), image_index);

    return vk_funcs->p_vkAcquireNextImageKHR(device->device, swapchain, timeout,
            semaphore, fence, image_index);
}

VkResult WINAPI wine_vkCreateDevice(VkPhysicalDevice phys_dev,
        const VkDeviceCreateInfo *create_info,
        const VkAllocationCallbacks *allocator, VkDevice *device)
{
    struct VkDevice_T *object = NULL;
    VkResult res;

    TRACE("%p %p %p %p\n", phys_dev, create_info, allocator, device);

    if (allocator)
    {
        FIXME("Support for allocation callbacks not implemented yet\n");
    }

    object = heap_alloc_zero(sizeof(*object));
    if (!object)
        return VK_ERROR_OUT_OF_HOST_MEMORY;

    object->base.loader_magic = VULKAN_ICD_MAGIC_VALUE;

    /* At least for now we can directly pass create_info through. All extensions we report
     * should be compatible. In addition the loader is supposed to sanitize values e.g. layers.
     */
    res = phys_dev->instance->funcs.p_vkCreateDevice(phys_dev->phys_dev,
            create_info, NULL /* allocator */, &object->device);
    if (res != VK_SUCCESS)
    {
        ERR("Failed to create device\n");
        goto err;
    }

    object->phys_dev = phys_dev;

    /* Just load all function pointers we are aware off. The loader takes care of filtering.
     * We use vkGetDeviceProcAddr as opposed to vkGetInstanceProcAddr for efficiency reasons
     * as functions pass through fewer dispatch tables within the loader.
     */
#define USE_VK_FUNC(name) \
    object->funcs.p_##name = (void *)vk_funcs->p_vkGetDeviceProcAddr(object->device, #name); \
    if (object->funcs.p_##name == NULL) \
        TRACE("Not found %s\n", #name);
    ALL_VK_DEVICE_FUNCS()
#undef USE_VK_FUNC

    *device = object;
    return VK_SUCCESS;

err:
    wine_vk_device_free(object);
    return res;
}

static VkResult WINAPI wine_vkCreateInstance(const VkInstanceCreateInfo *create_info,
        const VkAllocationCallbacks *allocator, VkInstance *instance)
{
    struct VkInstance_T *object = NULL;
    VkInstanceCreateInfo create_info_host;
    VkResult res;

    TRACE("create_info %p, allocator %p, instance %p\n", create_info, allocator, instance);

    if (allocator)
        FIXME("Support for allocation callbacks not implemented yet\n");

    object = heap_alloc_zero(sizeof(*object));
    if (!object)
    {
        ERR("Failed to allocate memory for instance\n");
        res = VK_ERROR_OUT_OF_HOST_MEMORY;
        goto err;
    }
    object->base.loader_magic = VULKAN_ICD_MAGIC_VALUE;

    res = wine_vk_instance_convert_create_info(create_info, &create_info_host);
    if (res != VK_SUCCESS)
    {
        ERR("Failed to convert instance create info, res=%d\n", res);
        goto err;
    }

    res = vk_funcs->p_vkCreateInstance(&create_info_host, NULL /* allocator */, &object->instance);
    if (res != VK_SUCCESS)
    {
        ERR("Failed to create instance, res=%d\n", res);
        goto err;
    }

    /* Load all instance functions we are aware of. Note the loader takes care
     * of any filtering for extensions which were not requested, but which the
     * ICD may support.
     */
#define USE_VK_FUNC(name) \
    object->funcs.p_##name = (void *)vk_funcs->p_vkGetInstanceProcAddr(object->instance, #name);
    ALL_VK_INSTANCE_FUNCS()
#undef USE_VK_FUNC

    /* Cache physical devices for vkEnumeratePhysicalDevices within the instance as
     * each vkPhysicalDevice is a dispatchable object, which means we need to wrap
     * the native physical device and present those the application.
     * Cleanup happens as part of wine_vkDestroyInstance.
     */
    res = wine_vk_instance_load_physical_devices(object);
    if (res != VK_SUCCESS)
    {
        ERR("Failed to cache physical devices, res=%d\n", res);
        goto err;
    }

    *instance = object;
    TRACE("Done, instance=%p native_instance=%p\n", object, object->instance);
    return VK_SUCCESS;

err:
    wine_vk_instance_free(object);
    return res;
}

#if defined(USE_STRUCT_CONVERSION)
static inline void convert_VkSwapchainCreateInfoKHR_win_to_host(const VkSwapchainCreateInfoKHR *in,
        VkSwapchainCreateInfoKHR_host *out)
{
    if (!in) return;

    out->sType = in->sType;
    out->pNext = in->pNext;
    out->flags = in->flags;
    out->surface = in->surface;
    out->minImageCount = in->minImageCount;
    out->imageFormat = in->imageFormat;
    out->imageColorSpace = in->imageColorSpace;
    out->imageExtent = in->imageExtent;
    out->imageArrayLayers = in->imageArrayLayers;
    out->imageUsage = in->imageUsage;
    out->imageSharingMode = in->imageSharingMode;
    out->queueFamilyIndexCount = in->queueFamilyIndexCount;
    out->pQueueFamilyIndices = in->pQueueFamilyIndices;
    out->preTransform = in->preTransform;
    out->compositeAlpha = in->compositeAlpha;
    out->presentMode = in->presentMode;
    out->clipped = in->clipped;
    out->oldSwapchain = in->oldSwapchain;
}
#endif

VkResult WINAPI wine_vkCreateSwapchainKHR(VkDevice device,
        const VkSwapchainCreateInfoKHR *create_info,
        const VkAllocationCallbacks *allocator, VkSwapchainKHR *swapchain)
{
#if defined(USE_STRUCT_CONVERSION)
    VkSwapchainCreateInfoKHR_host create_info_host;
    TRACE("%p %p %p %p\n", device, create_info, allocator, swapchain);

    if (allocator)
        FIXME("Support allocation allocators\n");

    convert_VkSwapchainCreateInfoKHR_win_to_host(create_info, &create_info_host);

    /* Wine graphics driver only uses structs in host format. */
    return vk_funcs->p_vkCreateSwapchainKHR(device->device,
            (VkSwapchainCreateInfoKHR *)&create_info_host, allocator, swapchain);
#else
    TRACE("%p %p %p %p\n", device, create_info, allocator, swapchain);

    if (allocator)
        FIXME("Support allocation allocators\n");

    return vk_funcs->p_vkCreateSwapchainKHR(device->device, create_info, allocator, swapchain);
#endif
}

VkResult WINAPI wine_vkCreateWin32SurfaceKHR(VkInstance instance,
        const VkWin32SurfaceCreateInfoKHR *create_info,
        const VkAllocationCallbacks* allocator, VkSurfaceKHR* surface)
{
    TRACE("%p %p %p %p\n", instance, create_info, allocator, surface);

    if (allocator)
        FIXME("Support allocation allocators\n");

    return vk_funcs->p_vkCreateWin32SurfaceKHR(instance->instance, create_info,
            NULL /* allocator */, surface);
}

void WINAPI wine_vkDestroyDevice(VkDevice device, const VkAllocationCallbacks *allocator)
{
    TRACE("%p %p\n", device, allocator);

    if (allocator)
        FIXME("Support for allocation callbacks not implemented yet\n");

    wine_vk_device_free(device);
}

void WINAPI wine_vkDestroyInstance(VkInstance instance, const VkAllocationCallbacks *allocator)
{
    TRACE("%p, %p\n", instance, allocator);

    if (allocator)
        FIXME("Support allocation allocators\n");

    wine_vk_instance_free(instance);
}

void WINAPI wine_vkDestroySurfaceKHR(VkInstance instance, VkSurfaceKHR surface,
        const VkAllocationCallbacks *allocator)
{
    TRACE("%p, 0x%s, %p\n", instance, wine_dbgstr_longlong(surface), allocator);

    if (allocator)
        FIXME("Support allocation allocators\n");

    vk_funcs->p_vkDestroySurfaceKHR(instance->instance, surface, NULL /* allocator */);
}

void WINAPI wine_vkDestroySwapchainKHR(VkDevice device, VkSwapchainKHR swapchain,
        const VkAllocationCallbacks *allocator)
{
    TRACE("%p, 0x%s %p\n", device, wine_dbgstr_longlong(swapchain), allocator);

    if (allocator)
        FIXME("Support allocation allocators\n");

    vk_funcs->p_vkDestroySwapchainKHR(device->device, swapchain, NULL /* allocator */);
}

VkResult WINAPI wine_vkEnumerateDeviceExtensionProperties(VkPhysicalDevice phys_dev,
        const char *layer_name, uint32_t *count, VkExtensionProperties *properties)
{
    TRACE("%p, %p, %p, %p\n", phys_dev, layer_name, count, properties);

    /* This shouldn't get called with layer_name set, the ICD loader prevents it. */
    if (layer_name)
    {
        ERR("Layer enumeration not supported from ICD.\n");
        return VK_ERROR_LAYER_NOT_PRESENT;
    }

    if (!properties)
    {
        *count = 0; /* No extensions yet. */
        return VK_SUCCESS;
    }

    /* When properties is not NULL, we copy the extensions over and set count to
     * the number of copied extensions. For now we don't have much to do as we don't support
     * any extensions yet.
     */
    *count = 0;
    return VK_SUCCESS;
}

static VkResult WINAPI wine_vkEnumerateInstanceExtensionProperties(const char *layer_name,
        uint32_t *count, VkExtensionProperties *properties)
{
    TRACE("%p %p %p\n", layer_name, count, properties);
    return vk_funcs->p_vkEnumerateInstanceExtensionProperties(layer_name, count, properties);
}

VkResult WINAPI wine_vkEnumeratePhysicalDevices(VkInstance instance, uint32_t *device_count,
        VkPhysicalDevice *devices)
{
    VkResult res;
    unsigned int i, num_copies;

    TRACE("%p %p %p\n", instance, device_count, devices);

    if (!devices)
    {
        *device_count = instance->num_phys_devs;
        return VK_SUCCESS;
    }

    if (*device_count < instance->num_phys_devs)
    {
        /* Incomplete is a type of success used to signal the application
         * that not all devices got copied.
         */
        num_copies = *device_count;
        res = VK_INCOMPLETE;
    }
    else
    {
        num_copies = instance->num_phys_devs;
        res = VK_SUCCESS;
    }

    for (i = 0; i < num_copies; i++)
    {
        devices[i] = instance->phys_devs[i];
    }
    *device_count = num_copies;

    TRACE("Returning %u devices\n", *device_count);
    return res;
}

PFN_vkVoidFunction WINAPI wine_vkGetDeviceProcAddr(VkDevice device, const char *name)
{
    void *func;
    TRACE("%p, %s\n", device, debugstr_a(name));

    /* The spec leaves return value undefined for a NULL device, let's just return NULL. */
    if (!device || !name)
        return NULL;

    /* Per the spec, we are only supposed to return device functions as in functions
     * for which the first parameter is vkDevice or a child of vkDevice like a
     * vkCommandBuffer or vkQueue.
     * Loader takes are of filtering of extensions which are enabled or not.
     */
    func = wine_vk_get_device_proc_addr(name);
    if (func)
        return func;

    TRACE("Function %s not found\n", debugstr_a(name));
    return NULL;
}

static PFN_vkVoidFunction WINAPI wine_vkGetInstanceProcAddr(VkInstance instance, const char *name)
{
    void *func;

    TRACE("%p %s\n", instance, debugstr_a(name));

    if (!name)
        return NULL;

    /* vkGetInstanceProcAddr can load most Vulkan functions when an instance is passed in, however
     * for a NULL instance it can only load global functions.
     */
    func = wine_vk_get_global_proc_addr(name);
    if (func)
    {
        return func;
    }
    if (!instance)
    {
        FIXME("Global function '%s' not found\n", debugstr_a(name));
        return NULL;
    }

    func = wine_vk_get_instance_proc_addr(name);
    if (func) return func;

    /* vkGetInstanceProcAddr also loads any children of instance, so device functions as well. */
    func = wine_vk_get_device_proc_addr(name);
    if (func) return func;

    FIXME("Unsupported device or instance function: '%s'\n", debugstr_a(name));
    return NULL;
}

VkResult WINAPI wine_vkGetPhysicalDeviceSurfaceCapabilitiesKHR(VkPhysicalDevice phys_dev,
        VkSurfaceKHR surface, VkSurfaceCapabilitiesKHR *capabilities)
{
    TRACE("%p, 0x%s, %p\n", phys_dev, wine_dbgstr_longlong(surface), capabilities);
    return vk_funcs->p_vkGetPhysicalDeviceSurfaceCapabilitiesKHR(phys_dev->phys_dev,
            surface, capabilities);
}

VkResult WINAPI wine_vkGetPhysicalDeviceSurfaceFormatsKHR(VkPhysicalDevice phys_dev,
        VkSurfaceKHR surface, uint32_t *format_count, VkSurfaceFormatKHR *formats)
{
    TRACE("%p, 0x%s, %p, %p\n", phys_dev, wine_dbgstr_longlong(surface), format_count, formats);
    return vk_funcs->p_vkGetPhysicalDeviceSurfaceFormatsKHR(phys_dev->phys_dev,
            surface, format_count, formats);
}

VkResult WINAPI wine_vkGetPhysicalDeviceSurfacePresentModesKHR(VkPhysicalDevice phys_dev,
        VkSurfaceKHR surface, uint32_t *mode_count, VkPresentModeKHR *modes)
{
    TRACE("%p, 0x%s, %p, %p\n", phys_dev, wine_dbgstr_longlong(surface), mode_count, modes);
    return vk_funcs->p_vkGetPhysicalDeviceSurfacePresentModesKHR(phys_dev->phys_dev,
            surface, mode_count, modes);
}

VkResult WINAPI wine_vkGetPhysicalDeviceSurfaceSupportKHR(VkPhysicalDevice phys_dev,
        uint32_t queue_family_index, VkSurfaceKHR surface, VkBool32 *supported)
{
    TRACE("%p, %u, 0x%s, %p\n", phys_dev, queue_family_index, wine_dbgstr_longlong(surface), supported);
    return vk_funcs->p_vkGetPhysicalDeviceSurfaceSupportKHR(phys_dev->phys_dev,
            queue_family_index, surface, supported);
}

VkBool32 WINAPI wine_vkGetPhysicalDeviceWin32PresentationSupportKHR(VkPhysicalDevice phys_dev,
        uint32_t queue_family_index)
{
    TRACE("%p %u\n", phys_dev, queue_family_index);
    return vk_funcs->p_vkGetPhysicalDeviceWin32PresentationSupportKHR(phys_dev->phys_dev,
            queue_family_index);
}

VkResult WINAPI wine_vkGetSwapchainImagesKHR(VkDevice device, VkSwapchainKHR swapchain,
        uint32_t *image_count, VkImage *images)
{
    TRACE("%p, 0x%s %p %p\n", device, wine_dbgstr_longlong(swapchain), image_count, images);
    return vk_funcs->p_vkGetSwapchainImagesKHR(device->device, swapchain,
            image_count, images);
}

VkResult WINAPI wine_vkQueuePresentKHR(VkQueue queue, const VkPresentInfoKHR *present_info)
{
    FIXME("stub: %p, %p\n", queue, present_info);
    return VK_ERROR_OUT_OF_HOST_MEMORY;
}

void * WINAPI wine_vk_icdGetInstanceProcAddr(VkInstance instance, const char *name)
{
    TRACE("%p %s\n", instance, debugstr_a(name));

    /* Initial version of the Vulkan ICD spec required vkGetInstanceProcAddr to be
     * exported. vk_icdGetInstanceProcAddr was added later to separete ICD calls from
     * Vulkan API. One of them in our case should forward to the other, so just forward
     * to the older vkGetInstanceProcAddr.
     */
    return wine_vkGetInstanceProcAddr(instance, name);
}

VkResult WINAPI wine_vk_icdNegotiateLoaderICDInterfaceVersion(uint32_t *supported_version)
{
    uint32_t req_version;

    TRACE("%p\n", supported_version);

    /* The spec is not clear how to handle this. Mesa drivers don't check, but it
     * is probably best to not explode. VK_INCOMPLETE seems to be the closest value.
     */
    if (!supported_version)
        return VK_INCOMPLETE;

    req_version = *supported_version;
    *supported_version = min(req_version, WINE_VULKAN_ICD_VERSION);
    TRACE("Loader requested ICD version %u, returning %u\n", req_version, *supported_version);

    return VK_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, void *reserved)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinst);
            return wine_vk_init();
    }
    return TRUE;
}

static const struct vulkan_func vk_global_dispatch_table[] =
{
    {"vkCreateInstance", &wine_vkCreateInstance},
    {"vkEnumerateInstanceExtensionProperties", &wine_vkEnumerateInstanceExtensionProperties},
    {"vkGetInstanceProcAddr", &wine_vkGetInstanceProcAddr},
};

static void *wine_vk_get_global_proc_addr(const char *name)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(vk_global_dispatch_table); i++)
    {
        if (strcmp(name, vk_global_dispatch_table[i].name) == 0)
        {
            TRACE("Found name=%s in global table\n", debugstr_a(name));
            return vk_global_dispatch_table[i].func;
        }
    }
    return NULL;
}
