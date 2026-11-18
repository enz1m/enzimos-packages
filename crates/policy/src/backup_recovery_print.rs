// SPDX-License-Identifier: MIT
//! Bounded descriptor-only recovery PDF. Rendering never submits a print job.
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json};
use std::{
    ffi::{CString, c_char, c_int, c_void},
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};
use unicode_general_category::{GeneralCategory as Category, get_general_category};
use zeroize::Zeroizing;
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const DOCUMENT_LIMIT: u64 = 16 * 1024 * 1024;
#[repr(C)]
#[derive(Default)]
struct Rectangle {
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
}
#[repr(C)]
struct LinePrefix {
    layout: *mut c_void,
    start: c_int,
    length: c_int,
}
#[link(name = "cairo")]
#[allow(
    unsafe_code,
    reason = "Declares Cairo/Pango PDF rendering and GObject release APIs."
)]
unsafe extern "C" {
    fn cairo_pdf_surface_create_for_stream(
        write: unsafe extern "C" fn(*mut c_void, *const u8, u32) -> c_int,
        closure: *mut c_void,
        width: f64,
        height: f64,
    ) -> *mut c_void;
    fn cairo_surface_status(surface: *mut c_void) -> c_int;
    fn cairo_surface_finish(surface: *mut c_void);
    fn cairo_surface_destroy(surface: *mut c_void);
    fn cairo_create(surface: *mut c_void) -> *mut c_void;
    fn cairo_status(context: *mut c_void) -> c_int;
    fn cairo_destroy(context: *mut c_void);
    fn cairo_set_font_size(context: *mut c_void, size: f64);
    fn cairo_move_to(context: *mut c_void, x: f64, y: f64);
    fn cairo_show_text(context: *mut c_void, text: *const c_char);
    fn cairo_show_page(context: *mut c_void);
}
#[link(name = "pangocairo-1.0")]
#[allow(
    unsafe_code,
    reason = "Declares Cairo/Pango PDF rendering and GObject release APIs."
)]
unsafe extern "C" {
    fn pango_cairo_create_layout(context: *mut c_void) -> *mut c_void;
    fn pango_cairo_show_layout_line(context: *mut c_void, line: *mut c_void);
}
#[link(name = "pango-1.0")]
#[allow(
    unsafe_code,
    reason = "Declares Cairo/Pango PDF rendering and GObject release APIs."
)]
unsafe extern "C" {
    fn pango_font_description_from_string(text: *const c_char) -> *mut c_void;
    fn pango_font_description_free(font: *mut c_void);
    fn pango_layout_set_font_description(layout: *mut c_void, font: *mut c_void);
    fn pango_layout_set_width(layout: *mut c_void, width: c_int);
    fn pango_layout_set_wrap(layout: *mut c_void, wrap: c_int);
    fn pango_layout_set_text(layout: *mut c_void, text: *const c_char, length: c_int);
    fn pango_layout_get_unknown_glyphs_count(layout: *mut c_void) -> c_int;
    fn pango_attr_list_new() -> *mut c_void;
    fn pango_attr_list_unref(attrs: *mut c_void);
    fn pango_attr_insert_hyphens_new(insert: c_int) -> *mut c_void;
    fn pango_attr_list_insert(attrs: *mut c_void, attribute: *mut c_void);
    fn pango_layout_set_attributes(layout: *mut c_void, attrs: *mut c_void);
    fn pango_layout_get_iter(layout: *mut c_void) -> *mut c_void;
    fn pango_layout_iter_free(iter: *mut c_void);
    fn pango_layout_iter_get_line_readonly(iter: *mut c_void) -> *mut c_void;
    fn pango_layout_iter_get_line_extents(
        iter: *mut c_void,
        ink: *mut Rectangle,
        logical: *mut Rectangle,
    );
    fn pango_layout_iter_get_baseline(iter: *mut c_void) -> c_int;
    fn pango_layout_iter_next_line(iter: *mut c_void) -> c_int;
}
#[link(name = "gobject-2.0")]
#[allow(
    unsafe_code,
    reason = "Declares Cairo/Pango PDF rendering and GObject release APIs."
)]
unsafe extern "C" {
    fn g_object_unref(object: *mut c_void);
}
struct Owned {
    pointer: *mut c_void,
    free: unsafe extern "C" fn(*mut c_void),
}
impl Owned {
    #[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
    fn new(pointer: *mut c_void, free: unsafe extern "C" fn(*mut c_void)) -> Result<Self> {
        require(!pointer.is_null(), "recovery renderer unavailable")?;
        Ok(Self { pointer, free })
    }
}
impl Drop for Owned {
    #[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
    fn drop(&mut self) {
        unsafe { (self.free)(self.pointer) }
    }
}
struct Sink {
    file: File,
    position: u64,
    failed: bool,
    initial: files::FileIdentity,
}
#[allow(unsafe_code, reason = "Linux syscall ABI (pwrite).")]
unsafe extern "C" fn write(closure: *mut c_void, bytes: *const u8, length: u32) -> c_int {
    // No Rust allocation, panic or secret-bearing error crosses the C boundary.
    let sink = unsafe { &mut *closure.cast::<Sink>() };
    if sink.failed
        || sink
            .position
            .checked_add(u64::from(length))
            .is_none_or(|n| n > DOCUMENT_LIMIT)
    {
        sink.failed = true;
        return 11;
    }
    let mut done = 0usize;
    let mut interrupted = 0;
    while done < length as usize {
        let count = unsafe {
            libc::pwrite(
                sink.file.as_raw_fd(),
                bytes.add(done).cast(),
                length as usize - done,
                (sink.position + done as u64) as libc::off_t,
            )
        };
        if count < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            && interrupted < 8
        {
            interrupted += 1;
            continue;
        }
        if count <= 0 {
            sink.failed = true;
            return 11;
        }
        done += count as usize;
    }
    sink.position += u64::from(length);
    0
}
fn printable(text: &str) -> Result<()> {
    require(
        !text.is_empty()
            && text.chars().all(|c| {
                !matches!(
                    get_general_category(c),
                    Category::Control
                        | Category::Format
                        | Category::Surrogate
                        | Category::PrivateUse
                        | Category::Unassigned
                        | Category::LineSeparator
                        | Category::ParagraphSeparator
                )
            }),
        "recovery text cannot be rendered safely",
    )
}
#[allow(unsafe_code, reason = "Cairo/Pango rendering ABI.")]
unsafe fn header(context: *mut c_void) {
    unsafe {
        cairo_set_font_size(context, 19.0);
        cairo_move_to(context, 48.0, 55.0);
        cairo_show_text(context, c"enzimOS recovery password".as_ptr());
        cairo_set_font_size(context, 10.0);
        cairo_move_to(context, 48.0, 77.0);
        cairo_show_text(
            context,
            c"Keep this paper separate from your computer and backup drive.".as_ptr(),
        );
        cairo_move_to(context, 48.0, 92.0);
        cairo_show_text(
            context,
            c"Join wrapped lines without adding spaces or punctuation.".as_ptr(),
        );
    }
}
#[allow(unsafe_code, reason = "Cairo/Pango rendering ABI.")]
fn footer(context: *mut c_void, page: u32) -> Result<()> {
    let text = CString::new(format!("Recovery password - page {page}"))
        .map_err(|_| Error("recovery footer encoding".into()))?;
    unsafe {
        cairo_set_font_size(context, 10.0);
        cairo_move_to(context, 48.0, 808.0);
        cairo_show_text(context, text.as_ptr());
    }
    Ok(())
}
#[allow(unsafe_code, reason = "Cairo/Pango rendering ABI.")]
pub fn render(input: File, output: File) -> Result<Value> {
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    require(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } == 0
            && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "private recovery renderer required",
    )?;
    let source = input.metadata()?;
    let target = output.metadata()?;
    for m in [&source, &target] {
        require(
            m.is_file()
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 0,
            "account-owned private RAM files required",
        )?;
    }
    let source_epoch = files::identity(&source);
    require(
        (source.dev(), source.ino()) != (target.dev(), target.ino())
            && (1..=4096).contains(&source.len())
            && target.len() == 0,
        "distinct bounded source and empty document required",
    )?;
    let seals = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GET_SEALS) };
    let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
    require(
        seals >= 0
            && seals & SEALS == SEALS
            && unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GET_SEALS) } == 0
            && flags >= 0
            && flags & libc::O_ACCMODE == libc::O_RDWR
            && flags & libc::O_APPEND == 0,
        "sealed input and unsealed document required",
    )?;
    let bytes = Zeroizing::new(files::read_file(&input, 4096, None, false)?);
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error("recovery text encoding refused".into()))?;
    printable(text)?;
    let mut sink = Box::new(Sink {
        initial: files::identity(&target),
        file: output,
        position: 0,
        failed: false,
    });
    let pages = {
        let surface = Owned::new(
            unsafe {
                cairo_pdf_surface_create_for_stream(
                    write,
                    (&mut *sink as *mut Sink).cast(),
                    595.0,
                    842.0,
                )
            },
            cairo_surface_destroy,
        )?;
        require(
            unsafe { cairo_surface_status(surface.pointer) } == 0,
            "recovery PDF surface refused",
        )?;
        let context = Owned::new(unsafe { cairo_create(surface.pointer) }, cairo_destroy)?;
        require(
            unsafe { cairo_status(context.pointer) } == 0,
            "recovery PDF context refused",
        )?;
        let layout = Owned::new(
            unsafe { pango_cairo_create_layout(context.pointer) },
            g_object_unref,
        )?;
        let font = Owned::new(
            unsafe { pango_font_description_from_string(c"monospace 13".as_ptr()) },
            pango_font_description_free,
        )?;
        let attrs = Owned::new(unsafe { pango_attr_list_new() }, pango_attr_list_unref)?;
        let attribute = unsafe { pango_attr_insert_hyphens_new(0) };
        require(
            !attribute.is_null(),
            "recovery wrapping attributes unavailable",
        )?;
        unsafe {
            pango_layout_set_font_description(layout.pointer, font.pointer);
            pango_layout_set_width(layout.pointer, 499 * 1024);
            pango_layout_set_wrap(layout.pointer, 1);
            pango_layout_set_text(layout.pointer, bytes.as_ptr().cast(), bytes.len() as c_int);
            pango_attr_list_insert(attrs.pointer, attribute);
            pango_layout_set_attributes(layout.pointer, attrs.pointer);
        }
        require(
            unsafe { pango_layout_get_unknown_glyphs_count(layout.pointer) } == 0,
            "recovery font has unknown glyphs",
        )?;
        let iter = Owned::new(
            unsafe { pango_layout_get_iter(layout.pointer) },
            pango_layout_iter_free,
        )?;
        let mut page = 1;
        let mut y = 119.0;
        let mut lines = 0;
        unsafe { header(context.pointer) };
        loop {
            lines += 1;
            require(lines <= 4096, "recovery line bound")?;
            let line = unsafe { pango_layout_iter_get_line_readonly(iter.pointer) };
            require(!line.is_null(), "recovery line unavailable")?;
            let prefix = unsafe { &*line.cast::<LinePrefix>() };
            require(
                prefix.start >= 0 && prefix.length > 0,
                "nonempty recovery line required",
            )?;
            let start = prefix.start as usize;
            let end = start
                .checked_add(prefix.length as usize)
                .ok_or_else(|| Error("recovery line range".into()))?;
            let segment = text
                .get(start..end)
                .ok_or_else(|| Error("recovery line encoding boundary".into()))?;
            require(
                !segment.starts_with(char::is_whitespace)
                    && !segment.ends_with(char::is_whitespace),
                "recovery wrap would lose whitespace",
            )?;
            let mut logical = Rectangle::default();
            unsafe {
                pango_layout_iter_get_line_extents(
                    iter.pointer,
                    std::ptr::null_mut(),
                    &mut logical,
                );
            };
            let height = f64::from(logical.height) / 1024.0;
            let baseline = (i64::from(unsafe { pango_layout_iter_get_baseline(iter.pointer) })
                - i64::from(logical.y)) as f64
                / 1024.0;
            require(
                height > 0.0 && height < 660.0,
                "recovery line geometry refused",
            )?;
            if y + height > 780.0 {
                footer(context.pointer, page)?;
                unsafe { cairo_show_page(context.pointer) };
                page += 1;
                require(page <= 8, "recovery document page bound")?;
                y = 119.0;
                unsafe { header(context.pointer) };
            }
            unsafe {
                cairo_move_to(context.pointer, 48.0, y + baseline);
                pango_cairo_show_layout_line(context.pointer, line);
            };
            y += height;
            require(
                !sink.failed && unsafe { cairo_status(context.pointer) } == 0,
                "recovery PDF output failed",
            )?;
            if unsafe { pango_layout_iter_next_line(iter.pointer) } == 0 {
                break;
            }
        }
        footer(context.pointer, page)?;
        unsafe { cairo_surface_finish(surface.pointer) };
        require(
            !sink.failed && unsafe { cairo_surface_status(surface.pointer) } == 0,
            "recovery PDF finalization failed",
        )?;
        page
    };
    require(
        files::identity(&input.metadata()?) == source_epoch,
        "original recovery input changed",
    )?;
    let m = sink.file.metadata()?;
    require(
        (m.dev(), m.ino()) == (sink.initial.0, sink.initial.1)
            && m.uid() == target.uid()
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 0
            && m.len() == sink.position
            && sink.position > 0
            && sink.position <= DOCUMENT_LIMIT,
        "original recovery document changed",
    )?;
    require(
        unsafe { libc::fcntl(sink.file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } == 0
            && unsafe { libc::fcntl(sink.file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS,
        "recovery document sealing failed",
    )?;
    Ok(
        json!({"schema":1,"status":"recovery-print-document-ready","pages":pages,"sealed_document":true,
        "print_submitted":false,"confirmation_recorded":false,"physical_copy_verified":false}),
    )
}
