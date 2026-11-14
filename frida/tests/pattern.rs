//! Tests for the pattern compiler, which run the real compiler on small patterns in a temporary
//! directory. The patterns and what is expected of them follow frida-core's own test of the
//! API, `compile-and-decode` in `tests/test-compiler.vala`.

use frida::{
    Error, Frida, PatternByteOrder, PatternCompileOptions, PatternCompiler, PatternDecodeOptions,
    PatternModule, PatternTypeKind, PatternTypeRefKind, PatternVisualizerArgumentKind,
    PatternVisualizerPresentation, Variant,
};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

// Frida-core is a process-wide singleton, so all tests that talk to it must
// serialize (same convention as `compile_script.rs`).
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    let _frida = &*FRIDA;
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

const PLAYER_PATTERN: &str = "
#pragma abi native

struct Vec3 {
\tfloat x;
\tfloat y;
\tfloat z;
};

struct Player {
\tu32 hitpoints;
\tu16 armor;
\tVec3 position;
\tPlayer *next;
};
";

/// A project directory with `patterns` in it, by file name.
fn project(patterns: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, source) in patterns {
        std::fs::write(dir.path().join(name), source).expect("write pattern");
    }
    dir
}

/// Options for a 64-bit little-endian target, with the project rooted at `project`.
fn options(project: &tempfile::TempDir) -> PatternCompileOptions {
    let options = PatternCompileOptions::new();
    options.set_project_root(project.path().to_str().expect("utf-8 path"));
    options.set_platform("darwin");
    options.set_arch("arm64");
    options
}

/// The pattern `name` of `project`, compiled, which must leave nothing to diagnose.
fn compiled(project: &tempfile::TempDir, name: &str) -> PatternModule {
    let module = PatternCompiler::new()
        .compile(name, Some(&options(project)))
        .expect("the pattern should be readable");
    let diagnostics: Vec<_> = module
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.message())
        .collect();
    assert_eq!(diagnostics, [] as [String; 0], "{name}");
    module
}

/// A player with 94 hitpoints, 7 armor, at the origin, whose `next` is 0x1234.
fn player_bytes() -> [u8; 32] {
    let mut data = [0; 32];
    data[0] = 94;
    data[4] = 7;
    data[24] = 0x34;
    data[25] = 0x12;
    data
}

#[test]
fn compile_options_keep_what_they_are_set_to() {
    let _serial = serial_guard();
    let options = PatternCompileOptions::new();
    let defaults = (
        options.project_root(),
        options.platform(),
        options.arch(),
        options.defines(),
    );
    let defines = HashMap::from([
        ("NAME".to_owned(), Variant::String("value".to_owned())),
        ("ENABLED".to_owned(), Variant::Boolean(true)),
        ("LEVEL".to_owned(), Variant::Int64(-3)),
    ]);

    options.set_project_root("/some/project");
    options.set_platform("linux");
    options.set_arch("x64");
    options.set_defines(&defines).unwrap();
    let unsupported = options.set_defines(&HashMap::from([(
        "LIST".to_owned(),
        Variant::StringList(vec![]),
    )]));

    assert_eq!(defaults, (None, None, None, HashMap::new()));
    assert_eq!(options.project_root().as_deref(), Some("/some/project"));
    assert_eq!(options.platform().as_deref(), Some("linux"));
    assert_eq!(options.arch().as_deref(), Some("x64"));
    assert_eq!(options.defines(), defines, "a rejected set changes nothing");
    assert!(
        matches!(&unsupported, Err(Error::PatternFailed { message, .. }) if message.contains("LIST")),
        "{unsupported:?}"
    );
}

#[test]
fn decode_options_keep_their_inputs() {
    let _serial = serial_guard();
    let options = PatternDecodeOptions::new();
    let inputs = HashMap::from([("scale".to_owned(), Variant::Int64(3))]);

    let by_default = options.inputs();
    options.set_inputs(&inputs).unwrap();
    let set = options.inputs();
    options.set_inputs(&HashMap::new()).unwrap();

    assert_eq!(by_default, HashMap::new());
    assert_eq!(set, inputs);
    assert_eq!(options.inputs(), HashMap::new());
}

#[test]
fn compiles_the_types_a_pattern_declares() {
    let _serial = serial_guard();
    let project = project(&[("player.pat", PLAYER_PATTERN)]);

    let module = compiled(&project, "player.pat");

    let types = module.types();
    let names: Vec<_> = types.iter().map(|declared| declared.name()).collect();
    assert_eq!(names, ["Vec3", "Player"]);
    assert_eq!(module.root_type(), None);
    assert!(module.inputs().is_empty());
    let player = &types[1];
    assert_eq!(
        (player.file().as_str(), player.line(), player.character()),
        ("player.pat", 9, 0)
    );
    assert_eq!(player.kind(), PatternTypeKind::Struct);
    assert_eq!((player.size(), player.align()), (32, 8));
    assert_eq!(player.doc(), None);
    assert!(player.values().is_empty() && player.bits().is_empty());
    assert!(player.underlying().is_none() && player.target().is_none());
    assert!(module.lookup("Player").is_some());
    assert!(module.lookup("Nope").is_none());
    assert!(module.lookup("Play\0er").is_none());
}

#[test]
fn describes_the_fields_of_a_struct() {
    let _serial = serial_guard();
    let project = project(&[("player.pat", PLAYER_PATTERN)]);
    let player = compiled(&project, "player.pat").lookup("Player").unwrap();

    let fields = player.fields();

    let layout: Vec<_> = fields
        .iter()
        .map(|field| (field.name(), field.offset(), field.size()))
        .collect();
    assert_eq!(
        layout,
        [
            ("hitpoints".to_owned(), 0, 4),
            ("armor".to_owned(), 4, 2),
            ("position".to_owned(), 8, 12),
            ("next".to_owned(), 24, 8),
        ]
    );
    let hitpoints = fields[0].type_ref().unwrap();
    assert_eq!(hitpoints.kind(), PatternTypeRefKind::Primitive);
    assert_eq!(hitpoints.name().as_deref(), Some("u32"));
    assert_eq!(hitpoints.display(), "u32");
    assert_eq!(hitpoints.order(), PatternByteOrder::Native);
    let position = fields[2].type_ref().unwrap();
    assert_eq!(position.kind(), PatternTypeRefKind::Named);
    assert_eq!(position.name().as_deref(), Some("Vec3"));
    let next = fields[3].type_ref().unwrap();
    assert_eq!(next.kind(), PatternTypeRefKind::Pointer);
    assert_eq!(
        next.target().and_then(|target| target.name()).as_deref(),
        Some("Player")
    );
    assert!(next.width().is_none(), "a native pointer");
    assert!(next.element().is_none());
    for field in &fields {
        assert!(!field.hidden() && !field.conditional() && !field.no_unique_address());
        assert_eq!(field.doc(), None);
    }
}

#[test]
fn describes_enums_bitfields_arrays_and_aliases() {
    let _serial = serial_guard();
    let project = project(&[(
        "kinds.hexpat",
        "enum Color : u8 { Red, Green = 5 };\n\
         bitfield Flags { visible : 1; level : 3; };\n\
         using Id = u16;\n\
         struct Record { Color color; be u32 big; u8 bytes[4]; };\n",
    )]);

    let module = compiled(&project, "kinds.hexpat");

    let color = module.lookup("Color").unwrap();
    assert_eq!(color.kind(), PatternTypeKind::Enum);
    assert_eq!(
        color
            .underlying()
            .and_then(|underlying| underlying.name())
            .as_deref(),
        Some("u8")
    );
    let values: Vec<_> = color
        .values()
        .iter()
        .map(|value| (value.name(), value.value(), value.last(), value.doc()))
        .collect();
    assert_eq!(
        values,
        [
            ("Red".to_owned(), 0, 0, None),
            ("Green".to_owned(), 5, 5, None)
        ]
    );
    let flags = module.lookup("Flags").unwrap();
    assert_eq!(flags.kind(), PatternTypeKind::Bitfield);
    let bits: Vec<_> = flags
        .bits()
        .iter()
        .map(|bit| (bit.name(), bit.offset(), bit.bits(), bit.enum_name()))
        .collect();
    assert_eq!(
        bits,
        [
            ("visible".to_owned(), 0, 1, None),
            ("level".to_owned(), 1, 3, None)
        ]
    );
    let id = module.lookup("Id").unwrap();
    assert_eq!(id.kind(), PatternTypeKind::Alias);
    assert_eq!(
        id.target().and_then(|target| target.name()).as_deref(),
        Some("u16")
    );
    let record = module.lookup("Record").unwrap().fields();
    let big = record[1].type_ref().unwrap();
    assert_eq!(big.order(), PatternByteOrder::Big);
    assert_eq!(big.display(), "be u32");
    let bytes = record[2].type_ref().unwrap();
    assert_eq!(bytes.kind(), PatternTypeRefKind::Array);
    assert_eq!(bytes.length(), 4);
    assert!(!bytes.null_terminated());
    assert_eq!(
        bytes
            .element()
            .and_then(|element| element.name())
            .as_deref(),
        Some("u8")
    );
}

#[test]
fn follows_imports_and_names_the_root_type_after_the_file() {
    let _serial = serial_guard();
    let placed = format!("{PLAYER_PATTERN}Player player @ 0x10;\n");
    let project = project(&[
        ("player.pat", PLAYER_PATTERN),
        (
            "game.hexpat",
            "import player;\n\nstruct Game {\n\tPlayer hero;\n};\n",
        ),
        ("placed.hexpat", &placed),
    ]);

    let game = compiled(&project, "game.hexpat");
    let placed = compiled(&project, "placed.hexpat");

    let game_type = game.lookup("Game").unwrap();
    assert_eq!(
        (game_type.file().as_str(), game_type.size()),
        ("game.hexpat", 32)
    );
    assert_eq!(game.lookup("Player").unwrap().file(), "player.pat");
    assert_eq!(placed.root_type().as_deref(), Some("Placed"));
    let root = placed.lookup("Placed").unwrap();
    assert_eq!(root.file(), "placed.hexpat");
    assert_eq!(root.fields()[0].name(), "player");
}

#[test]
fn diagnoses_a_pattern_that_does_not_compile() {
    let _serial = serial_guard();
    let project = project(&[
        ("broken.pat", "struct A { auto a @ 0; };\n"),
        ("importing-broken.hexpat", "import broken;\n"),
    ]);
    let compiler = PatternCompiler::new();
    let options = options(&project);

    let broken = compiler.compile("broken.pat", Some(&options)).unwrap();
    let importing = compiler
        .compile("importing-broken.hexpat", Some(&options))
        .unwrap();
    let missing = compiler.compile("missing.hexpat", Some(&options));
    let with_nul = compiler.compile("bro\0ken.pat", Some(&options));

    assert!(broken.types().is_empty());
    let diagnostics: Vec<_> = broken
        .diagnostics()
        .iter()
        .map(|diagnostic| {
            (
                diagnostic.file(),
                diagnostic.line(),
                diagnostic.character(),
                diagnostic.message(),
            )
        })
        .collect();
    assert_eq!(
        diagnostics,
        [(
            "broken.pat".to_owned(),
            0,
            11,
            "auto is not supported".to_owned()
        )]
    );
    assert_eq!(importing.diagnostics()[0].file(), "broken.pat");
    assert!(
        matches!(&missing, Err(Error::PatternFailed { message, .. }) if !message.is_empty()),
        "{:?}",
        missing.as_ref().err()
    );
    assert!(matches!(with_nul, Err(Error::CStringFailed)));
}

#[test]
fn lays_types_out_as_its_defines_say() {
    let _serial = serial_guard();
    let project = project(&[(
        "layout.hexpat",
        "#ifdef WIDE\nstruct Layout { u16 value; };\n#else\nstruct Layout { u8 value; };\n#endif\n",
    )]);
    let wide_options = options(&project);
    wide_options
        .set_defines(&HashMap::from([(
            "WIDE".to_owned(),
            Variant::String(String::new()),
        )]))
        .unwrap();

    let narrow = compiled(&project, "layout.hexpat");
    let wide = PatternCompiler::new()
        .compile("layout.hexpat", Some(&wide_options))
        .unwrap();
    let wide_value = wide.decode("Layout", &[1, 2], 0, None).unwrap();

    assert_eq!(narrow.lookup("Layout").unwrap().size(), 1);
    assert_eq!(wide.lookup("Layout").unwrap().size(), 2);
    assert_eq!(wide_value.fields()[0].value(), Some(Variant::Int64(0x201)));
}

#[test]
fn decodes_bytes_as_a_type() {
    let _serial = serial_guard();
    let project = project(&[("player.pat", PLAYER_PATTERN)]);
    let module = compiled(&project, "player.pat");

    let player = module
        .decode("Player", &player_bytes(), 0x1000, None)
        .unwrap();

    assert_eq!(player.type_name(), "Player");
    assert_eq!(
        (player.address(), player.offset(), player.size()),
        (0x1000, 0, 32)
    );
    assert_eq!(player.name(), "", "the root has no name");
    assert_eq!(player.value(), None, "a struct has no value of its own");
    assert!(!player.truncated());
    assert!(player.elements().is_empty());
    let fields = player.fields();
    let scalars: Vec<_> = fields
        .iter()
        .map(|field| (field.name(), field.address(), field.value()))
        .collect();
    assert_eq!(
        scalars,
        [
            ("hitpoints".to_owned(), 0x1000, Some(Variant::Int64(94))),
            ("armor".to_owned(), 0x1004, Some(Variant::Int64(7))),
            ("position".to_owned(), 0x1008, None),
            ("next".to_owned(), 0x1018, Some(Variant::Int64(0x1234))),
        ]
    );
    let x = &fields[2].fields()[0];
    assert_eq!(x.value_as_f64(), Some(0.0));
    assert_eq!(x.value(), Some(Variant::Unsupported("d".to_owned())));
    assert_eq!(fields[0].value_as_f64(), None, "an integer is not a float");
    let hitpoints = &fields[0];
    assert_eq!(
        (
            hitpoints.label(),
            hitpoints.display_name(),
            hitpoints.formatted(),
            hitpoints.comment(),
            hitpoints.color()
        ),
        (None, None, None, None, None)
    );
    assert!(!hitpoints.hidden() && !hitpoints.inlined() && !hitpoints.sealed());
    assert_eq!(
        (hitpoints.bit_offset(), hitpoints.bits(), hitpoints.count()),
        (-1, 0, -1)
    );
    assert_eq!(hitpoints.section(), 0);
    assert!(hitpoints.visualizer().is_none());
    let ids: std::collections::HashSet<_> = fields.iter().map(|field| field.id()).collect();
    assert_eq!(ids.len(), fields.len(), "each value has an id of its own");
}

#[test]
fn serializes_a_decoded_value() {
    let _serial = serial_guard();
    let project = project(&[("player.pat", PLAYER_PATTERN)]);
    let player = compiled(&project, "player.pat")
        .decode("Player", &player_bytes(), 0x1000, None)
        .unwrap();

    let serialized = player.to_variant();

    let map = serialized.get_map().expect("a dictionary");
    assert_eq!(map.get("type"), Some(&Variant::String("Player".to_owned())));
    assert_eq!(map.get("address"), Some(&Variant::Int64(0x1000)));
    let fields = map
        .get("fields")
        .and_then(|fields| fields.get_maplist())
        .expect("the fields, each a dictionary");
    assert_eq!(fields.len(), 4);
    assert_eq!(
        fields[0].get("name"),
        Some(&Variant::String("hitpoints".to_owned()))
    );
    assert_eq!(fields[0].get("value"), Some(&Variant::Int64(94)));
}

#[test]
fn reports_what_the_data_was_too_short_for() {
    let _serial = serial_guard();
    let project = project(&[("player.pat", PLAYER_PATTERN)]);
    let module = compiled(&project, "player.pat");

    let truncated = module
        .decode("Player", &player_bytes()[..20], 0x1000, None)
        .unwrap();
    let unknown = module.decode("Nope", &player_bytes(), 0, None);
    let with_nul = module.decode("Pla\0yer", &player_bytes(), 0, None);

    assert!(truncated.truncated());
    assert_eq!(truncated.fields()[3].value(), None);
    assert!(
        matches!(&unknown, Err(Error::PatternFailed { message, .. }) if message.contains("unknown type Nope")),
        "{:?}",
        unknown.as_ref().err()
    );
    assert!(matches!(with_nul, Err(Error::CStringFailed)));
}

#[test]
fn decodes_with_the_inputs_it_is_given() {
    let _serial = serial_guard();
    let project = project(&[(
        "configurable.hexpat",
        "u32 scale in = 1;\nstruct Sample { u8 raw; u32 scaled = raw * scale [[export]]; };\nSample sample @ 0;\n",
    )]);
    let module = compiled(&project, "configurable.hexpat");
    let decode_options = PatternDecodeOptions::new();
    decode_options
        .set_inputs(&HashMap::from([("scale".to_owned(), Variant::Int64(3))]))
        .unwrap();

    let inputs = module.inputs();
    let scaled = module
        .decode("Configurable", &[7], 0, Some(&decode_options))
        .unwrap();

    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].name(), "scale");
    assert_eq!(
        inputs[0]
            .type_ref()
            .and_then(|declared| declared.name())
            .as_deref(),
        Some("u32")
    );
    assert_eq!(
        scaled.fields()[0].fields()[1].value(),
        Some(Variant::Int64(21))
    );
}

#[test]
fn carries_the_formatting_a_pattern_asks_for() {
    let _serial = serial_guard();
    let formatted = format!(
        "{PLAYER_PATTERN}\nfn describe(u32 hp) {{ return std::format(\"{{}} hp\", hp); }}\n\
         struct Labelled {{ u32 hitpoints [[format(\"describe\"), color(\"00FF00\")]]; }};\n"
    );
    let project = project(&[("formatted.hexpat", &formatted)]);

    let labelled = compiled(&project, "formatted.hexpat")
        .decode("Labelled", &player_bytes(), 0, None)
        .unwrap();

    let hitpoints = &labelled.fields()[0];
    assert_eq!(hitpoints.formatted().as_deref(), Some("94 hp"));
    assert_eq!(hitpoints.color().as_deref(), Some("00FF00"));
}

#[test]
fn carries_the_visualizers_a_pattern_asks_for() {
    let _serial = serial_guard();
    let project = project(&[(
        "visualizing.hexpat",
        "
struct Image {
\tu8 magic[2];
\tu8 width;
\tu8 visualizer[3] @ addressof(this) [[sealed, hex::visualize(\"image\", this), no_unique_address]];
\tu8 samples[2] [[hex::inline_visualize(\"line_plot\", this, width)]];
};
",
    )]);

    let image = compiled(&project, "visualizing.hexpat")
        .decode("Image", &[0x89, 0x50, 7, 1, 2], 0x1000, None)
        .unwrap();

    let fields = image.fields();
    assert!(fields[2].sealed());
    assert_eq!(fields[0].count(), 2);
    assert_eq!(fields[0].elements().len(), 2);
    let detached = fields[2]
        .visualizer()
        .expect("a visualizer on the third field");
    assert_eq!(detached.name(), "image");
    assert_eq!(
        detached.presentation(),
        PatternVisualizerPresentation::Detached
    );
    let arguments = detached.arguments();
    let bytes = &arguments[0];
    assert_eq!(bytes.kind(), PatternVisualizerArgumentKind::Pattern);
    assert_eq!((bytes.address(), bytes.size()), (0x1000, 3));
    assert_eq!(bytes.pattern(), fields[2].id());
    assert_eq!(bytes.data().as_deref(), Some(&[0x89, 0x50, 7][..]));
    let inline = fields[3]
        .visualizer()
        .expect("a visualizer on the fourth field");
    assert_eq!(inline.presentation(), PatternVisualizerPresentation::Inline);
    let arguments = inline.arguments();
    assert_eq!(arguments.len(), 2);
    assert_eq!(arguments[1].kind(), PatternVisualizerArgumentKind::Value);
    assert_eq!(arguments[1].value(), Some(Variant::Int64(7)));
    assert_eq!(arguments[1].data(), None);
    assert!(inline.to_variant().get_map().is_some());
    assert!(arguments[1].to_variant().get_map().is_some());
    assert!(
        fields[2]
            .to_variant()
            .get_map()
            .is_some_and(|map| map.contains_key("visualizer"))
    );
}

#[test]
fn calls_a_function_of_the_pattern_with_a_decoded_value() {
    let _serial = serial_guard();
    let project = project(&[(
        "printing.hexpat",
        "
fn describe(ref auto pattern) { std::print(\"width {}\", pattern.width); };
struct Image { u8 magic[2]; u8 width; };
",
    )]);
    let module = compiled(&project, "printing.hexpat");

    let output = module.call_function("Image", &[0x89, 0x50, 7], 0x1000, 1, "describe", None);
    let unknown = module.call_function("Image", &[0x89, 0x50, 7], 0x1000, 1, "nope", None);

    assert_eq!(output.ok().as_deref(), Some("width 7"));
    assert!(
        matches!(&unknown, Err(Error::PatternFailed { .. })),
        "{unknown:?}"
    );
}
