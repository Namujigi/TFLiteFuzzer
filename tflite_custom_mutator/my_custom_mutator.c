#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

// AFL++ types (minimal forward declarations)
typedef struct afl_state afl_state_t;
typedef uint8_t u8;
#define MAX_FILE (32*1024*1024L)

#define TFLITE_IDENTIFIER_0 0x54  // 'T'
#define TFLITE_IDENTIFIER_1 0x46  // 'F'
#define TFLITE_IDENTIFIER_2 0x4C  // 'L'
#define TFLITE_IDENTIFIER_3 0x33  // '3'

#define MIN_TFLITE_SIZE 8
#define SAFE_MUTATION_THRESHOLD 0.9

// Model VTable offsets
#define MODEL_VT_VERSION 4
#define MODEL_VT_OPERATOR_CODES 6
#define MODEL_VT_SUBGRAPHS 8
#define MODEL_VT_DESCRIPTION 10
#define MODEL_VT_BUFFERS 12
#define MODEL_VT_METADATA_BUFFER 14
#define MODEL_VT_METADATA 16
#define MODEL_VT_SIGNATURE_DEFS 18

// SignatureDef VTable offsets
#define SIGNATURE_VT_INPUTS 4
#define SIGNATURE_VT_OUTPUTS 6
#define SIGNATURE_VT_SIGNATURE_KEY 8
#define SIGNATURE_VT_SUBGRAPH_INDEX 10

// Metadata VTable offsets
#define METADATA_VT_NAME 4
#define METADATA_VT_BUFFER 6

// Buffer VTable offsets
#define BUFFER_VT_DATA 4
#define BUFFER_VT_OFFSET 6
#define BUFFER_VT_SIZE 8

// SubGraph VTable offsets
#define SUBGRAPH_VT_TENSORS 4
#define SUBGRAPH_VT_INPUTS 6
#define SUBGRAPH_VT_OUTPUTS 8
#define SUBGRAPH_VT_OPERATORS 10
#define SUBGRAPH_VT_NAME 12

// OperatorCode VTable offsets
#define OPERATORCODE_VT_DEPRECATED_BUILTIN_CODE 4
#define OPERATORCODE_VT_CUSTOM_CODE 6
#define OPERATORCODE_VT_VERSION 8
#define OPERATORCODE_VT_BUILTIN_CODE 10

// Known interesting integers
static const int32_t INTERESTING_INT32[] = {
    0, 1, -1,
    0x7FFFFFFF,  // INT32_MAX
    0x80000000,  // INT32_MIN
    255, 256, 257,
    65535, 65536, 65537,
    -255, -256, -257
};
#define NUM_INTERESTING_INT32 (sizeof(INTERESTING_INT32) / sizeof(int32_t))

// Helper functions
static inline uint32_t read_u32_le(const uint8_t *data) {
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static inline void write_u32_le(uint8_t *data, uint32_t value) {
    data[0] = value & 0xFF;
    data[1] = (value >> 8) & 0xFF;
    data[2] = (value >> 16) & 0xFF;
    data[3] = (value >> 24) & 0xFF;
}

static inline uint16_t read_u16_le(const uint8_t *data) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static inline void write_u16_le(uint8_t *data, uint16_t value) {
    data[0] = value & 0xFF;
    data[1] = (value >> 8) & 0xFF;
}

static inline int32_t read_i32_le(const uint8_t *data) {
    return (int32_t)read_u32_le(data);
}

static inline void write_i32_le(uint8_t *data, int32_t value) {
    write_u32_le(data, (uint32_t)value);
}

static inline uint64_t read_u64_le(const uint8_t *data) {
    uint64_t lo = read_u32_le(data);
    uint64_t hi = read_u32_le(data + 4);
    return lo | (hi << 32);
}

static inline void write_u64_le(uint8_t *data, uint64_t value) {
    write_u32_le(data, (uint32_t)(value & 0xFFFFFFFF));
    write_u32_le(data + 4, (uint32_t)(value >> 32));
}

static inline int64_t read_i64_le(const uint8_t *data) {
    return (int64_t)read_u64_le(data);
}

static inline void write_i64_le(uint8_t *data, int64_t value) {
    write_u64_le(data, (uint64_t)value);
}

// Mutator state
typedef struct {
    afl_state_t* afl;
    u8* fuzz_buf;
    size_t fuzz_buf_capacity;

    uint64_t mutation_count;
    uint64_t safe_mutations;
    uint64_t unsafe_mutations;
} custom_mutator_t;

// Parsed structure info
typedef struct {
    uint32_t model_vtable_offset;
    uint32_t model_table_offset;

    uint32_t signature_defs_vector_offset;
    uint32_t num_signature_defs;

    uint32_t metadata_vector_offset;
    uint32_t num_metadata;

    uint32_t buffers_vector_offset;
    uint32_t num_buffers;

    uint32_t subgraphs_vector_offset;
    uint32_t num_subgraphs;

    uint32_t operator_codes_vector_offset;
    uint32_t num_operator_codes;
} ParsedInfo;

// Field selection result
typedef struct {
    uint32_t offset;      // 변이할 필드의 파일 내 위치
    uint32_t max_size;    // 변이 가능한 최대 바이트 수
} FieldLocation;

// Validation
static bool is_valid_tflite(const uint8_t *buf, size_t size) {
    if (size < MIN_TFLITE_SIZE) return false;

    if (buf[4] != TFLITE_IDENTIFIER_0 ||
        buf[5] != TFLITE_IDENTIFIER_1 ||
        buf[6] != TFLITE_IDENTIFIER_2 ||
        buf[7] != TFLITE_IDENTIFIER_3) {
        return false;
    }

    uint32_t root_offset = read_u32_le(buf);
    if (root_offset != 0x1C) return false;

    return true;
}

// Structure parsing
static bool parse_structure_info(uint8_t* buf, size_t size, ParsedInfo* info) {
    memset(info, 0, sizeof(ParsedInfo));

    uint32_t root_offset = 0x1C; // root offset 고정.
    info->model_table_offset = root_offset;

    if (root_offset + 4 >= size) return false; // 연산하는 중간에 계속해서 파일 내부 위치인지 검증

    int32_t vtable_soffset = -(int32_t)read_u32_le(buf + root_offset);
    uint32_t vtable_offset = root_offset + vtable_soffset;

    if (vtable_offset >= size || vtable_offset + 4 >= size) return false;
    info->model_vtable_offset = vtable_offset;

    uint8_t* vtable = buf + vtable_offset;
    uint16_t vtable_size = read_u16_le(vtable);

    if (vtable_size < 4 || vtable_offset + vtable_size > size) return false;

    // Parse each vector
    if (vtable_size > MODEL_VT_SIGNATURE_DEFS) {
        uint16_t sig_offset = read_u16_le(vtable + MODEL_VT_SIGNATURE_DEFS);
        if (sig_offset != 0) { // 필드 유효한지(Nullptr이 아닌지) 검증
            uint32_t sig_pos = root_offset + sig_offset;
            if (sig_pos + 4 <= size) {
                uint32_t sig_uoffset = read_u32_le(buf + sig_pos);
                uint32_t sig_vec = sig_pos + sig_uoffset;
                if (sig_vec + 4 <= size) {
                    info->signature_defs_vector_offset = sig_vec; // Model->signature_defs()
                    info->num_signature_defs = read_u32_le(buf + sig_vec); // Model->signature_defs()->size()
                }
            }
        }
    }

    if (vtable_size > MODEL_VT_METADATA) {
        uint16_t meta_offset = read_u16_le(vtable + MODEL_VT_METADATA);
        if (meta_offset != 0) {
            uint32_t meta_pos = root_offset + meta_offset;
            if (meta_pos + 4 <= size) {
                uint32_t meta_uoffset = read_u32_le(buf + meta_pos);
                uint32_t meta_vec = meta_pos + meta_uoffset;
                if (meta_vec + 4 <= size) {
                    info->metadata_vector_offset = meta_vec;
                    info->num_metadata = read_u32_le(buf + meta_vec);
                }
            }
        }
    }

    if (vtable_size > MODEL_VT_BUFFERS) {
        uint16_t buf_offset = read_u16_le(vtable + MODEL_VT_BUFFERS);
        if (buf_offset != 0) {
            uint32_t buf_pos = root_offset + buf_offset;
            if (buf_pos + 4 <= size) {
                uint32_t buf_uoffset = read_u32_le(buf + buf_pos);
                uint32_t buf_vec = buf_pos + buf_uoffset;
                if (buf_vec + 4 <= size) {
                    info->buffers_vector_offset = buf_vec;
                    info->num_buffers = read_u32_le(buf + buf_vec);
                }
            }
        }
    }

    if (vtable_size > MODEL_VT_SUBGRAPHS) {
        uint16_t sub_offset = read_u16_le(vtable + MODEL_VT_SUBGRAPHS);
        if (sub_offset != 0) {
            uint32_t sub_pos = root_offset + sub_offset;
            if (sub_pos + 4 <= size) {
                uint32_t sub_uoffset = read_u32_le(buf + sub_pos);
                uint32_t sub_vec = sub_pos + sub_uoffset;
                if (sub_vec + 4 <= size) {
                    info->subgraphs_vector_offset = sub_vec;
                    info->num_subgraphs = read_u32_le(buf + sub_vec);
                }
            }
        }
    }

    if (vtable_size > MODEL_VT_OPERATOR_CODES) {
        uint16_t op_offset = read_u16_le(vtable + MODEL_VT_OPERATOR_CODES);
        if (op_offset != 0) {
            uint32_t op_pos = root_offset + op_offset;
            if (op_pos + 4 <= size) {
                uint32_t op_uoffset = read_u32_le(buf + op_pos);
                uint32_t op_vec = op_pos + op_uoffset;
                if (op_vec + 4 <= size) {
                    info->operator_codes_vector_offset = op_vec;
                    info->num_operator_codes = read_u32_le(buf + op_vec);
                }
            }
        }
    }

    return true;
}

// Select randomizable field
static FieldLocation select_randomizable_field(uint8_t* buf, size_t size, ParsedInfo* info) {
    FieldLocation loc = {0, 0};
    int category = rand() % 7;

    switch (category) {
        case 0: // Model.version (uint32_t - 4 bytes)
            {
                uint16_t ver_offset = read_u16_le(buf + info->model_vtable_offset + MODEL_VT_VERSION);
                if (ver_offset == 0) return loc;
                loc.offset = info->model_table_offset + ver_offset;
                loc.max_size = 4;
                return loc;
            }

        case 1: // Model.description (String - uoffset 4 bytes)
            {
                uint16_t desc_offset = read_u16_le(buf + info->model_vtable_offset + MODEL_VT_DESCRIPTION);
                if (desc_offset == 0) return loc;
                loc.offset = info->model_table_offset + desc_offset;
                loc.max_size = 4;
                return loc;
            }

        case 2: // signature_defs - select random SignatureDef field
            if (info->num_signature_defs > 0) {
                uint32_t idx = rand() % info->num_signature_defs;
                
                // Model->signature_defs()->Get(idx) (== Offset<Signature>)
                uint32_t sig_elem_offset_pos = info->signature_defs_vector_offset + 4 + idx * 4;

                if (sig_elem_offset_pos + 4 > size) return loc;
                uint32_t sig_uoffset = read_u32_le(buf + sig_elem_offset_pos);
                // Signature 객체
                uint32_t sig_table = sig_elem_offset_pos + sig_uoffset;

                if (sig_table + 4 > size) return loc;
                int32_t sig_vtable_soffset = -(int32_t)read_u32_le(buf + sig_table);
                uint32_t sig_vtable = sig_table + sig_vtable_soffset;

                if (sig_vtable + 4 > size) return loc;
                uint16_t sig_vtable_size = read_u16_le(buf + sig_vtable); // Signature->size()

                // Select random field: inputs(4), outputs(6), signature_key(8), subgraph_index(10)
                int field_choice = rand() % 4;
                uint16_t field_vt = 0;
                uint32_t field_size = 0;

                if (field_choice == 0 && sig_vtable_size > SIGNATURE_VT_INPUTS) {
                    field_vt = SIGNATURE_VT_INPUTS;
                    field_size = 4; // Vector<Offset<TensorMap>>* - uoffset
                } else if (field_choice == 1 && sig_vtable_size > SIGNATURE_VT_OUTPUTS) {
                    field_vt = SIGNATURE_VT_OUTPUTS;
                    field_size = 4; // Vector<Offset<TensorMap>>* - uoffset
                } else if (field_choice == 2 && sig_vtable_size > SIGNATURE_VT_SIGNATURE_KEY) {
                    field_vt = SIGNATURE_VT_SIGNATURE_KEY;
                    field_size = 4; // String* - uoffset
                } else if (field_choice == 3 && sig_vtable_size > SIGNATURE_VT_SUBGRAPH_INDEX) {
                    field_vt = SIGNATURE_VT_SUBGRAPH_INDEX;
                    field_size = 4; // uint32_t
                } else {
                    return loc;
                }

                if (sig_vtable + field_vt + 2 > size) return loc;
                uint16_t field_offset = read_u16_le(buf + sig_vtable + field_vt);
                if (field_offset == 0) return loc;

                if (sig_table + field_offset + 4 > size) return loc;
                loc.offset = sig_table + field_offset;
                loc.max_size = field_size;
                return loc;
            }
            return loc;

        case 3: // metadata - select random Metadata field
            if (info->num_metadata > 0) {
                uint32_t idx = rand() % info->num_metadata;

                // Model->metadata()->Get(idx) (== Offset<Metadata>)
                uint32_t meta_elem_offset_pos = info->metadata_vector_offset + 4 + idx * 4;

                if (meta_elem_offset_pos + 4 > size) return loc;
                uint32_t meta_uoffset = read_u32_le(buf + meta_elem_offset_pos);
                // Metadata 객체
                uint32_t meta_table = meta_elem_offset_pos + meta_uoffset;

                if (meta_table + 4 > size) return loc;
                int32_t meta_vtable_soffset = -(int32_t)read_u32_le(buf + meta_table);
                uint32_t meta_vtable = meta_table + meta_vtable_soffset;

                if (meta_vtable + 4 > size) return loc;
                uint16_t meta_vtable_size = read_u16_le(buf + meta_vtable);

                // Select random field: name(4), buffer(6)
                int field_choice = rand() % 2;
                uint16_t field_vt = 0;
                uint32_t field_size = 0;

                if (field_choice == 0 && meta_vtable_size > METADATA_VT_NAME) {
                    field_vt = METADATA_VT_NAME;
                    field_size = 4; // String* - uoffset
                } else if (field_choice == 1 && meta_vtable_size > METADATA_VT_BUFFER) {
                    field_vt = METADATA_VT_BUFFER;
                    field_size = 4; // uint32_t
                } else {
                    return loc;
                }

                if (meta_vtable + field_vt + 2 > size) return loc;
                uint16_t field_offset = read_u16_le(buf + meta_vtable + field_vt);
                if (field_offset == 0) return loc;

                if (meta_table + field_offset + field_size > size) return loc;
                loc.offset = meta_table + field_offset;
                loc.max_size = field_size;
                return loc;
            }
            return loc;

        case 4: // buffers (skip buffers[0]) - select random Buffer field
            if (info->num_buffers > 1) {
                uint32_t idx = 1 + rand() % (info->num_buffers - 1);
                uint32_t buf_elem_offset_pos = info->buffers_vector_offset + 4 + idx * 4;

                if (buf_elem_offset_pos + 4 > size) return loc;
                uint32_t buf_uoffset = read_u32_le(buf + buf_elem_offset_pos);
                // Buffer 객체
                uint32_t buf_table = buf_elem_offset_pos + buf_uoffset;

                if (buf_table + 4 > size) return loc;
                int32_t buf_vtable_soffset = -(int32_t)read_u32_le(buf + buf_table);
                uint32_t buf_vtable = buf_table + buf_vtable_soffset;

                if (buf_vtable + 4 > size) return loc;
                uint16_t buf_vtable_size = read_u16_le(buf + buf_vtable);

                // Select random field: data(4), offset(6), size(8)
                int field_choice = rand() % 3;
                uint16_t field_vt = 0;
                uint32_t field_size = 0;

                if (field_choice == 0 && buf_vtable_size > BUFFER_VT_DATA) {
                    field_vt = BUFFER_VT_DATA;
                    field_size = 4; // Vector<uint8_t>* - uoffset
                } else if (field_choice == 1 && buf_vtable_size > BUFFER_VT_OFFSET) {
                    field_vt = BUFFER_VT_OFFSET;
                    field_size = 8; // uint64_t
                } else if (field_choice == 2 && buf_vtable_size > BUFFER_VT_SIZE) {
                    field_vt = BUFFER_VT_SIZE;
                    field_size = 8; // uint64_t
                } else {
                    return loc;
                }

                if (buf_vtable + field_vt + 2 > size) return loc;
                uint16_t field_offset = read_u16_le(buf + buf_vtable + field_vt);
                if (field_offset == 0) return loc;

                if (buf_table + field_offset + field_size > size) return loc;
                loc.offset = buf_table + field_offset;
                loc.max_size = field_size;
                return loc;
            }
            return loc;

        case 5: // subgraphs - select random SubGraph field
            if (info->num_subgraphs > 0) {
                uint32_t idx = rand() % info->num_subgraphs;
                uint32_t sub_elem_offset_pos = info->subgraphs_vector_offset + 4 + idx * 4;

                if (sub_elem_offset_pos + 4 > size) return loc;
                uint32_t sub_uoffset = read_u32_le(buf + sub_elem_offset_pos);
                // Subgraph 객체
                uint32_t sub_table = sub_elem_offset_pos + sub_uoffset;

                if (sub_table + 4 > size) return loc;
                int32_t sub_vtable_soffset = -(int32_t)read_u32_le(buf + sub_table);
                uint32_t sub_vtable = sub_table + sub_vtable_soffset;

                if (sub_vtable + 4 > size) return loc;
                uint16_t sub_vtable_size = read_u16_le(buf + sub_vtable);

                // Select random field: tensors(4), inputs(6), outputs(8), operators(10), name(12)
                int field_choice = rand() % 5;
                uint16_t field_vt = 0;
                uint32_t field_size = 0;

                if (field_choice == 0 && sub_vtable_size > SUBGRAPH_VT_TENSORS) {
                    field_vt = SUBGRAPH_VT_TENSORS;
                    field_size = 4; // Vector<Offset<Tensor>>* - uoffset
                } else if (field_choice == 1 && sub_vtable_size > SUBGRAPH_VT_INPUTS) {
                    field_vt = SUBGRAPH_VT_INPUTS;
                    field_size = 4; // Vector<int32_t>* - uoffset
                } else if (field_choice == 2 && sub_vtable_size > SUBGRAPH_VT_OUTPUTS) {
                    field_vt = SUBGRAPH_VT_OUTPUTS;
                    field_size = 4; // Vector<int32_t>* - uoffset
                } else if (field_choice == 3 && sub_vtable_size > SUBGRAPH_VT_OPERATORS) {
                    field_vt = SUBGRAPH_VT_OPERATORS;
                    field_size = 4; // Vector<Offset<Operator>>* - uoffset
                } else if (field_choice == 4 && sub_vtable_size > SUBGRAPH_VT_NAME) {
                    field_vt = SUBGRAPH_VT_NAME;
                    field_size = 4; // String* - uoffset
                } else {
                    return loc;
                }

                if (sub_vtable + field_vt + 2 > size) return loc;
                uint16_t field_offset = read_u16_le(buf + sub_vtable + field_vt);
                if (field_offset == 0) return loc;

                if (sub_table + field_offset + field_size > size) return loc;
                loc.offset = sub_table + field_offset;
                loc.max_size = field_size;
                return loc;
            }
            return loc;

        case 6: // operator_codes - select random OperatorCode field
            if (info->num_operator_codes > 0) {
                uint32_t idx = rand() % info->num_operator_codes;
                uint32_t op_elem_offset_pos = info->operator_codes_vector_offset + 4 + idx * 4;

                if (op_elem_offset_pos + 4 > size) return loc;
                uint32_t op_uoffset = read_u32_le(buf + op_elem_offset_pos);
                // OperatorCode 객체
                uint32_t op_table = op_elem_offset_pos + op_uoffset;

                if (op_table + 4 > size) return loc;
                int32_t op_vtable_soffset = -(int32_t)read_u32_le(buf + op_table);
                uint32_t op_vtable = op_table + op_vtable_soffset;

                if (op_vtable + 4 > size) return loc;
                uint16_t op_vtable_size = read_u16_le(buf + op_vtable);

                // Select random field: deprecated_builtin_code(4), custom_code(6), version(8), builtin_code(10)
                int field_choice = rand() % 4;
                uint16_t field_vt = 0;
                uint32_t field_size = 0;

                if (field_choice == 0 && op_vtable_size > OPERATORCODE_VT_DEPRECATED_BUILTIN_CODE) {
                    field_vt = OPERATORCODE_VT_DEPRECATED_BUILTIN_CODE;
                    field_size = 1; // int8_t
                } else if (field_choice == 1 && op_vtable_size > OPERATORCODE_VT_CUSTOM_CODE) {
                    field_vt = OPERATORCODE_VT_CUSTOM_CODE;
                    field_size = 4; // String* - uoffset
                } else if (field_choice == 2 && op_vtable_size > OPERATORCODE_VT_VERSION) {
                    field_vt = OPERATORCODE_VT_VERSION;
                    field_size = 4; // int32_t
                } else if (field_choice == 3 && op_vtable_size > OPERATORCODE_VT_BUILTIN_CODE) {
                    field_vt = OPERATORCODE_VT_BUILTIN_CODE;
                    field_size = 4; // BuiltinOperator (int32_t)
                } else {
                    return loc;
                }

                if (op_vtable + field_vt + 2 > size) return loc;
                uint16_t field_offset = read_u16_le(buf + op_vtable + field_vt);
                if (field_offset == 0) return loc;

                if (op_table + field_offset + field_size > size) return loc;
                loc.offset = op_table + field_offset;
                loc.max_size = field_size;
                return loc;
            }
            return loc;
    }

    return loc;
}

// Mutation Strategy 1-1: Bit Flip
static bool mutate_bit_flip(uint8_t* buf, size_t size, uint32_t pos, uint32_t max_size) {
    if (pos == 0 || pos >= size || max_size == 0) return false;
    if (pos + max_size > size) max_size = size - pos;

    // Flip bits within max_size range
    uint32_t num_flips = (rand() % 8) + 1;
    for (uint32_t i = 0; i < num_flips && i < max_size; i++) {
        uint32_t byte_pos = rand() % max_size;
        buf[pos + byte_pos] ^= (1 << (rand() % 8));
    }
    return true;
}

// Mutation Strategy 1-2: Integer Arithmetic
static bool mutate_integer_arithmetic(uint8_t* buf, size_t size, uint32_t pos, uint32_t max_size) {
    if (pos == 0 || pos >= size || max_size == 0) return false;

    // Select arithmetic operation based on field size
    if (max_size >= 8 && pos + 8 <= size) {
        // 64-bit arithmetic
        int64_t value = read_i64_le(buf + pos);
        int64_t delta = (rand() % 200) - 100;  // -100 ~ +99
        write_i64_le(buf + pos, value + delta);
    } else if (max_size >= 4 && pos + 4 <= size) {
        // 32-bit arithmetic
        int32_t value = read_i32_le(buf + pos);
        int32_t delta = (rand() % 100) - 50;  // -50 ~ +49
        write_i32_le(buf + pos, value + delta);
    } else if (max_size >= 2 && pos + 2 <= size) {
        // 16-bit arithmetic
        int16_t value = (int16_t)read_u16_le(buf + pos);
        int16_t delta = (rand() % 20) - 10;  // -10 ~ +9
        write_u16_le(buf + pos, (uint16_t)(value + delta));
    } else if (max_size >= 1 && pos + 1 <= size) {
        // 8-bit arithmetic
        int8_t value = (int8_t)buf[pos];
        int8_t delta = (rand() % 10) - 5;  // -5 ~ +4
        buf[pos] = (uint8_t)(value + delta);
    } else {
        return false;
    }
    return true;
}

// Mutation Strategy 1-3: Known Interesting Integer Insert
static bool mutate_known_interesting_integer_insert(uint8_t* buf, size_t size, uint32_t pos, uint32_t max_size) {
    if (pos == 0 || pos >= size || max_size == 0) return false;

    // Insert interesting value based on field size
    if (max_size >= 8 && pos + 8 <= size) {
        // 64-bit interesting value
        const int64_t interesting_64[] = {
            0, 1, -1,
            0x7FFFFFFFFFFFFFFFLL,  // INT64_MAX
            0x8000000000000000LL,  // INT64_MIN
            0xFFFFFFFF,            // UINT32_MAX as uint64
            0x100000000LL,         // 2^32
            -0xFFFFFFFF,
            65535, 65536, 65537,
            -65535, -65536
        };
        int64_t val = interesting_64[rand() % 12];
        write_i64_le(buf + pos, val);
    } else if (max_size >= 4 && pos + 4 <= size) {
        // 32-bit interesting value
        int32_t interesting = INTERESTING_INT32[rand() % NUM_INTERESTING_INT32];
        write_i32_le(buf + pos, interesting);
    } else if (max_size >= 2 && pos + 2 <= size) {
        // 16-bit interesting value (0, 1, -1, 255, 256, etc.)
        const int16_t interesting_16[] = {0, 1, -1, 255, 256, -255, -256};
        int16_t val = interesting_16[rand() % 7];
        write_u16_le(buf + pos, (uint16_t)val);
    } else if (max_size >= 1 && pos + 1 <= size) {
        // 8-bit interesting value
        const int8_t interesting_8[] = {0, 1, -1, 127, -128, 255};
        buf[pos] = (uint8_t)interesting_8[rand() % 6];
    } else {
        return false;
    }
    return true;
}

// Mutation Strategy 1-4: Random Bytes
static bool mutate_random_bytes(uint8_t* buf, size_t size, uint32_t pos, uint32_t max_size) {
    if (pos == 0 || pos >= size || max_size == 0) return false;
    if (pos + max_size > size) max_size = size - pos;

    // Randomize bytes within max_size range
    uint32_t len = (rand() % max_size) + 1;
    if (len > max_size) len = max_size;

    for (uint32_t i = 0; i < len; i++) {
        buf[pos + i] = rand() & 0xFF;
    }
    return true;
}

// Mutation Strategy 1: Randomizable field mutation
/*
    자유롭게 변경 가능한 필드 변이

    변이 가능한 필드:
    1. Model->signature_defs()->Get(i) (==Signature 객체) 내의 모든 필드(inputs, outputs, signature_key, subgraph_index)
    2. Model->metadata()->Get(i) (==Metadata 객체) 내의 모든 필드(name, buffer)
    3. Model->buffers()->Get(i) (==Buffer 객체) 내의 모든 필드(data, offset, size)
    4. Model->description() 내의 필드(flatbuffers::String*)
    5. Model->subgraphs()->Get(i) (==Subgraph 객체) 내의 모든 필드(tensors, inputs, outputs, operators, name, debug_metadata_index)
    6. Model->operator_codes()->Get(i) (==OperatorCode 객체) 내의 모든 필드(deprecated_builtin_code, custom_code, version, builtin_code)
    7. Model->version() (==uint32_t)
    
    * 이 이외에 추가적인 offset 연산을 통해 접근해야하는 객체(Tensor, Operator 등의 객체)의 구조는 고려 안 함.
*/
static bool mutate_randomizable_field(uint8_t* buf, size_t size) {
    ParsedInfo info;
    if (!parse_structure_info(buf, size, &info)) {
        return false;
    }

    FieldLocation loc = select_randomizable_field(buf, size, &info);
    // 한 번의 기회를 더 줌
    if (loc.offset == 0 || loc.max_size == 0) loc = select_randomizable_field(buf, size, &info);
    if (loc.offset == 0 || loc.max_size == 0) return false;

    int strategy = rand() % 4;
    switch (strategy) {
        case 0:
            return mutate_bit_flip(buf, size, loc.offset, loc.max_size);
        case 1:
            return mutate_integer_arithmetic(buf, size, loc.offset, loc.max_size);
        case 2:
            return mutate_known_interesting_integer_insert(buf, size, loc.offset, loc.max_size);
        case 3:
            return mutate_random_bytes(buf, size, loc.offset, loc.max_size);
    }
    return false;
}

// Mutation Strategy 2: VTable Field → 0 (nullptr)
/*
    Unsafe Mutation

    변이 대상 VTable:
    1. Model의 VTable
    2. Signature의 VTable
    3. Metadata의 VTable
    4. Buffer의 VTable
    5. Subgraph의 VTable
    6. OperatorCode의 VTable

    * VTable이 저장된 객체에 접근할 때도 유효한 주소인지 확인(연산)하면서 접근 필요.
*/
static bool mutate_vtable_field(uint8_t* buf, size_t size) {
    ParsedInfo info;
    if (!parse_structure_info(buf, size, &info)) {
        return false;
    }

    // Select random object type (0: Model, 1: Signature, 2: Metadata, 3: Buffer, 4: Subgraph, 5: OperatorCode)
    int obj_type = rand() % 6;

    uint32_t vtable_offset = 0;
    uint16_t vtable_size = 0;
    const uint16_t* removable_fields = NULL;
    int num_removable = 0;

    switch (obj_type) {
        case 0: // Model VTable
            {
                vtable_offset = info.model_vtable_offset;
                if (vtable_offset + 4 > size) return false;

                vtable_size = read_u16_le(buf + vtable_offset);
                if (vtable_size < 6) return false;

                static const uint16_t MODEL_REMOVABLE[] = {
                    MODEL_VT_VERSION,
                    MODEL_VT_OPERATOR_CODES,
                    MODEL_VT_SUBGRAPHS,
                    MODEL_VT_DESCRIPTION,
                    MODEL_VT_BUFFERS,
                    MODEL_VT_METADATA_BUFFER,
                    MODEL_VT_METADATA,
                    MODEL_VT_SIGNATURE_DEFS
                };
                removable_fields = MODEL_REMOVABLE;
                num_removable = 8;
            }
            break;

        case 1: // Signature VTable
            if (info.num_signature_defs == 0) return false;
            {
                uint32_t idx = rand() % info.num_signature_defs;
                uint32_t sig_elem_offset_pos = info.signature_defs_vector_offset + 4 + idx * 4;

                if (sig_elem_offset_pos + 4 > size) return false;
                uint32_t sig_uoffset = read_u32_le(buf + sig_elem_offset_pos);
                uint32_t sig_table = sig_elem_offset_pos + sig_uoffset;

                if (sig_table + 4 > size) return false;
                int32_t sig_vtable_soffset = -(int32_t)read_u32_le(buf + sig_table);
                vtable_offset = sig_table + sig_vtable_soffset;

                if (vtable_offset + 4 > size) return false;
                vtable_size = read_u16_le(buf + vtable_offset);
                if (vtable_size < 6) return false;

                static const uint16_t SIGNATURE_REMOVABLE[] = {
                    SIGNATURE_VT_INPUTS,
                    SIGNATURE_VT_OUTPUTS,
                    SIGNATURE_VT_SIGNATURE_KEY,
                    SIGNATURE_VT_SUBGRAPH_INDEX
                };
                removable_fields = SIGNATURE_REMOVABLE;
                num_removable = 4;
            }
            break;

        case 2: // Metadata VTable
            if (info.num_metadata == 0) return false;
            {
                uint32_t idx = rand() % info.num_metadata;
                uint32_t meta_elem_offset_pos = info.metadata_vector_offset + 4 + idx * 4;

                if (meta_elem_offset_pos + 4 > size) return false;
                uint32_t meta_uoffset = read_u32_le(buf + meta_elem_offset_pos);
                uint32_t meta_table = meta_elem_offset_pos + meta_uoffset;

                if (meta_table + 4 > size) return false;
                int32_t meta_vtable_soffset = -(int32_t)read_u32_le(buf + meta_table);
                vtable_offset = meta_table + meta_vtable_soffset;

                if (vtable_offset + 4 > size) return false;
                vtable_size = read_u16_le(buf + vtable_offset);
                if (vtable_size < 6) return false;

                static const uint16_t METADATA_REMOVABLE[] = {
                    METADATA_VT_NAME,
                    METADATA_VT_BUFFER
                };
                removable_fields = METADATA_REMOVABLE;
                num_removable = 2;
            }
            break;

        case 3: // Buffer VTable
            if (info.num_buffers <= 1) return false;
            {
                uint32_t idx = 1 + rand() % (info.num_buffers - 1);
                uint32_t buf_elem_offset_pos = info.buffers_vector_offset + 4 + idx * 4;

                if (buf_elem_offset_pos + 4 > size) return false;
                uint32_t buf_uoffset = read_u32_le(buf + buf_elem_offset_pos);
                uint32_t buf_table = buf_elem_offset_pos + buf_uoffset;

                if (buf_table + 4 > size) return false;
                int32_t buf_vtable_soffset = -(int32_t)read_u32_le(buf + buf_table);
                vtable_offset = buf_table + buf_vtable_soffset;

                if (vtable_offset + 4 > size) return false;
                vtable_size = read_u16_le(buf + vtable_offset);
                if (vtable_size < 6) return false;

                static const uint16_t BUFFER_REMOVABLE[] = {
                    BUFFER_VT_DATA,
                    BUFFER_VT_OFFSET,
                    BUFFER_VT_SIZE
                };
                removable_fields = BUFFER_REMOVABLE;
                num_removable = 3;
            }
            break;

        case 4: // Subgraph VTable
            if (info.num_subgraphs == 0) return false;
            {
                uint32_t idx = rand() % info.num_subgraphs;
                uint32_t sub_elem_offset_pos = info.subgraphs_vector_offset + 4 + idx * 4;

                if (sub_elem_offset_pos + 4 > size) return false;
                uint32_t sub_uoffset = read_u32_le(buf + sub_elem_offset_pos);
                uint32_t sub_table = sub_elem_offset_pos + sub_uoffset;

                if (sub_table + 4 > size) return false;
                int32_t sub_vtable_soffset = -(int32_t)read_u32_le(buf + sub_table);
                vtable_offset = sub_table + sub_vtable_soffset;

                if (vtable_offset + 4 > size) return false;
                vtable_size = read_u16_le(buf + vtable_offset);
                if (vtable_size < 6) return false;

                static const uint16_t SUBGRAPH_REMOVABLE[] = {
                    SUBGRAPH_VT_TENSORS,
                    SUBGRAPH_VT_INPUTS,
                    SUBGRAPH_VT_OUTPUTS,
                    SUBGRAPH_VT_OPERATORS,
                    SUBGRAPH_VT_NAME
                };
                removable_fields = SUBGRAPH_REMOVABLE;
                num_removable = 5;
            }
            break;

        case 5: // OperatorCode VTable
            if (info.num_operator_codes == 0) return false;
            {
                uint32_t idx = rand() % info.num_operator_codes;
                uint32_t op_elem_offset_pos = info.operator_codes_vector_offset + 4 + idx * 4;

                if (op_elem_offset_pos + 4 > size) return false;
                uint32_t op_uoffset = read_u32_le(buf + op_elem_offset_pos);
                uint32_t op_table = op_elem_offset_pos + op_uoffset;

                if (op_table + 4 > size) return false;
                int32_t op_vtable_soffset = -(int32_t)read_u32_le(buf + op_table);
                vtable_offset = op_table + op_vtable_soffset;

                if (vtable_offset + 4 > size) return false;
                vtable_size = read_u16_le(buf + vtable_offset);
                if (vtable_size < 6) return false;

                static const uint16_t OPERATORCODE_REMOVABLE[] = {
                    OPERATORCODE_VT_DEPRECATED_BUILTIN_CODE,
                    OPERATORCODE_VT_CUSTOM_CODE,
                    OPERATORCODE_VT_VERSION,
                    OPERATORCODE_VT_BUILTIN_CODE
                };
                removable_fields = OPERATORCODE_REMOVABLE;
                num_removable = 4;
            }
            break;

        default:
            return false;
    }

    // Select random removable field
    if (num_removable == 0) return false;
    uint16_t field_vt = removable_fields[rand() % num_removable];

    if (vtable_offset + field_vt + 2 > size) return false;
    if (field_vt >= vtable_size) return false;

    uint16_t current = read_u16_le(buf + vtable_offset + field_vt);
    if (current == 0) return false;  // Already null

    write_u16_le(buf + vtable_offset + field_vt, 0);
    return true;
}

// Mutation Strategy 3: Offset manipulation (soffset, voffset, uoffset)
/*
    Unsafe Mutation

    변이 대상 Offset:
    1. Table의 soffset (VTable을 가리키는 음수 offset, Table 첫 4바이트)
    2. VTable의 voffset (각 필드의 상대 offset, vtable_size/table_size 제외)
    3. Data Table의 uoffset (String, Vector 등을 가리키는 offset)

    변이 대상 객체:
    - Model, Signature, Metadata, Buffer, Subgraph, OperatorCode

    * offset이 저장된 Field를 포함한 객체에 접근할 때도 유효한 주소인지 확인(연산)하면서 접근 필요.
    * 변이된 Offset을 통해 계산된 주소값이 파일 범위 내에 있어야 함. (calculated_pos < size)
*/
static bool mutate_uoffset_field(uint8_t* buf, size_t size) {
    ParsedInfo info;
    if (!parse_structure_info(buf, size, &info)) {
        return false;
    }

    // Select random object type (0: Model, 1: Signature, 2: Metadata, 3: Buffer, 4: Subgraph, 5: OperatorCode)
    int obj_type = rand() % 6;

    uint32_t offset_pos = 0;
    uint32_t offset_size = 0; // 2 for voffset, 4 for soffset/uoffset

    switch (obj_type) {
        case 0: // Model
            {
                // Choose: 0=soffset, 1=voffset, 2=uoffset
                int offset_type = rand() % 3;

                if (offset_type == 0) {
                    // Table soffset (첫 4바이트, VTable 가리키는 음수 offset)
                    offset_pos = info.model_table_offset;
                    offset_size = 4;
                } else if (offset_type == 1) {
                    // VTable voffset (필드들의 상대 offset)
                    uint16_t vtable_size = read_u16_le(buf + info.model_vtable_offset);
                    if (vtable_size < 6) return false;

                    // Skip vtable_size(0-2) and table_size(2-4), mutate field offsets (4+)
                    uint32_t num_fields = (vtable_size - 4) / 2;
                    if (num_fields == 0) return false;

                    uint32_t field_idx = rand() % num_fields;
                    offset_pos = info.model_vtable_offset + 4 + field_idx * 2;
                    offset_size = 2;
                } else {
                    // Data Table uoffset
                    const uint16_t MODEL_UOFFSET_FIELDS[] = {
                        MODEL_VT_DESCRIPTION,
                        MODEL_VT_SIGNATURE_DEFS,
                        MODEL_VT_METADATA,
                        MODEL_VT_BUFFERS,
                        MODEL_VT_SUBGRAPHS,
                        MODEL_VT_OPERATOR_CODES
                    };
                    uint16_t field_vt = MODEL_UOFFSET_FIELDS[rand() % 6];

                    if (info.model_vtable_offset + field_vt + 2 > size) return false;
                    uint16_t field_offset = read_u16_le(buf + info.model_vtable_offset + field_vt);
                    if (field_offset == 0) return false;

                    offset_pos = info.model_table_offset + field_offset;
                    offset_size = 4;
                }
            }
            break;

        case 1: // Signature
            if (info.num_signature_defs == 0) return false;
            {
                uint32_t idx = rand() % info.num_signature_defs;
                uint32_t sig_elem_offset_pos = info.signature_defs_vector_offset + 4 + idx * 4;

                if (sig_elem_offset_pos + 4 > size) return false;
                uint32_t sig_uoffset = read_u32_le(buf + sig_elem_offset_pos);
                uint32_t sig_table = sig_elem_offset_pos + sig_uoffset;

                if (sig_table + 4 > size) return false;
                int32_t sig_vtable_soffset = -(int32_t)read_u32_le(buf + sig_table);
                uint32_t sig_vtable = sig_table + sig_vtable_soffset;

                if (sig_vtable + 4 > size) return false;

                // Choose: 0=soffset, 1=voffset, 2=uoffset
                int offset_type = rand() % 3;

                if (offset_type == 0) {
                    offset_pos = sig_table;
                    offset_size = 4;
                } else if (offset_type == 1) {
                    uint16_t vtable_size = read_u16_le(buf + sig_vtable);
                    if (vtable_size < 6) return false;

                    uint32_t num_fields = (vtable_size - 4) / 2;
                    if (num_fields == 0) return false;

                    uint32_t field_idx = rand() % num_fields;
                    offset_pos = sig_vtable + 4 + field_idx * 2;
                    offset_size = 2;
                } else {
                    const uint16_t SIG_UOFFSET_FIELDS[] = {
                        SIGNATURE_VT_INPUTS,
                        SIGNATURE_VT_OUTPUTS,
                        SIGNATURE_VT_SIGNATURE_KEY
                    };
                    uint16_t field_vt = SIG_UOFFSET_FIELDS[rand() % 3];

                    if (sig_vtable + field_vt + 2 > size) return false;
                    uint16_t field_offset = read_u16_le(buf + sig_vtable + field_vt);
                    if (field_offset == 0) return false;

                    offset_pos = sig_table + field_offset;
                    offset_size = 4;
                }
            }
            break;

        case 2: // Metadata
            if (info.num_metadata == 0) return false;
            {
                uint32_t idx = rand() % info.num_metadata;
                uint32_t meta_elem_offset_pos = info.metadata_vector_offset + 4 + idx * 4;

                if (meta_elem_offset_pos + 4 > size) return false;
                uint32_t meta_uoffset = read_u32_le(buf + meta_elem_offset_pos);
                uint32_t meta_table = meta_elem_offset_pos + meta_uoffset;

                if (meta_table + 4 > size) return false;
                int32_t meta_vtable_soffset = -(int32_t)read_u32_le(buf + meta_table);
                uint32_t meta_vtable = meta_table + meta_vtable_soffset;

                if (meta_vtable + 4 > size) return false;

                int offset_type = rand() % 3;

                if (offset_type == 0) {
                    offset_pos = meta_table;
                    offset_size = 4;
                } else if (offset_type == 1) {
                    uint16_t vtable_size = read_u16_le(buf + meta_vtable);
                    if (vtable_size < 6) return false;

                    uint32_t num_fields = (vtable_size - 4) / 2;
                    if (num_fields == 0) return false;

                    uint32_t field_idx = rand() % num_fields;
                    offset_pos = meta_vtable + 4 + field_idx * 2;
                    offset_size = 2;
                } else {
                    if (meta_vtable + METADATA_VT_NAME + 2 > size) return false;
                    uint16_t field_offset = read_u16_le(buf + meta_vtable + METADATA_VT_NAME);
                    if (field_offset == 0) return false;

                    offset_pos = meta_table + field_offset;
                    offset_size = 4;
                }
            }
            break;

        case 3: // Buffer
            if (info.num_buffers <= 1) return false;
            {
                uint32_t idx = 1 + rand() % (info.num_buffers - 1);
                uint32_t buf_elem_offset_pos = info.buffers_vector_offset + 4 + idx * 4;

                if (buf_elem_offset_pos + 4 > size) return false;
                uint32_t buf_uoffset = read_u32_le(buf + buf_elem_offset_pos);
                uint32_t buf_table = buf_elem_offset_pos + buf_uoffset;

                if (buf_table + 4 > size) return false;
                int32_t buf_vtable_soffset = -(int32_t)read_u32_le(buf + buf_table);
                uint32_t buf_vtable = buf_table + buf_vtable_soffset;

                if (buf_vtable + 4 > size) return false;

                int offset_type = rand() % 3;

                if (offset_type == 0) {
                    offset_pos = buf_table;
                    offset_size = 4;
                } else if (offset_type == 1) {
                    uint16_t vtable_size = read_u16_le(buf + buf_vtable);
                    if (vtable_size < 6) return false;

                    uint32_t num_fields = (vtable_size - 4) / 2;
                    if (num_fields == 0) return false;

                    uint32_t field_idx = rand() % num_fields;
                    offset_pos = buf_vtable + 4 + field_idx * 2;
                    offset_size = 2;
                } else {
                    if (buf_vtable + BUFFER_VT_DATA + 2 > size) return false;
                    uint16_t field_offset = read_u16_le(buf + buf_vtable + BUFFER_VT_DATA);
                    if (field_offset == 0) return false;

                    offset_pos = buf_table + field_offset;
                    offset_size = 4;
                }
            }
            break;

        case 4: // Subgraph
            if (info.num_subgraphs == 0) return false;
            {
                uint32_t idx = rand() % info.num_subgraphs;
                uint32_t sub_elem_offset_pos = info.subgraphs_vector_offset + 4 + idx * 4;

                if (sub_elem_offset_pos + 4 > size) return false;
                uint32_t sub_uoffset = read_u32_le(buf + sub_elem_offset_pos);
                uint32_t sub_table = sub_elem_offset_pos + sub_uoffset;

                if (sub_table + 4 > size) return false;
                int32_t sub_vtable_soffset = -(int32_t)read_u32_le(buf + sub_table);
                uint32_t sub_vtable = sub_table + sub_vtable_soffset;

                if (sub_vtable + 4 > size) return false;

                int offset_type = rand() % 3;

                if (offset_type == 0) {
                    offset_pos = sub_table;
                    offset_size = 4;
                } else if (offset_type == 1) {
                    uint16_t vtable_size = read_u16_le(buf + sub_vtable);
                    if (vtable_size < 6) return false;

                    uint32_t num_fields = (vtable_size - 4) / 2;
                    if (num_fields == 0) return false;

                    uint32_t field_idx = rand() % num_fields;
                    offset_pos = sub_vtable + 4 + field_idx * 2;
                    offset_size = 2;
                } else {
                    const uint16_t SUB_UOFFSET_FIELDS[] = {
                        SUBGRAPH_VT_TENSORS,
                        SUBGRAPH_VT_INPUTS,
                        SUBGRAPH_VT_OUTPUTS,
                        SUBGRAPH_VT_OPERATORS,
                        SUBGRAPH_VT_NAME
                    };
                    uint16_t field_vt = SUB_UOFFSET_FIELDS[rand() % 5];

                    if (sub_vtable + field_vt + 2 > size) return false;
                    uint16_t field_offset = read_u16_le(buf + sub_vtable + field_vt);
                    if (field_offset == 0) return false;

                    offset_pos = sub_table + field_offset;
                    offset_size = 4;
                }
            }
            break;

        case 5: // OperatorCode
            if (info.num_operator_codes == 0) return false;
            {
                uint32_t idx = rand() % info.num_operator_codes;
                uint32_t op_elem_offset_pos = info.operator_codes_vector_offset + 4 + idx * 4;

                if (op_elem_offset_pos + 4 > size) return false;
                uint32_t op_uoffset = read_u32_le(buf + op_elem_offset_pos);
                uint32_t op_table = op_elem_offset_pos + op_uoffset;

                if (op_table + 4 > size) return false;
                int32_t op_vtable_soffset = -(int32_t)read_u32_le(buf + op_table);
                uint32_t op_vtable = op_table + op_vtable_soffset;

                if (op_vtable + 4 > size) return false;

                int offset_type = rand() % 3;

                if (offset_type == 0) {
                    offset_pos = op_table;
                    offset_size = 4;
                } else if (offset_type == 1) {
                    uint16_t vtable_size = read_u16_le(buf + op_vtable);
                    if (vtable_size < 6) return false;

                    uint32_t num_fields = (vtable_size - 4) / 2;
                    if (num_fields == 0) return false;

                    uint32_t field_idx = rand() % num_fields;
                    offset_pos = op_vtable + 4 + field_idx * 2;
                    offset_size = 2;
                } else {
                    if (op_vtable + OPERATORCODE_VT_CUSTOM_CODE + 2 > size) return false;
                    uint16_t field_offset = read_u16_le(buf + op_vtable + OPERATORCODE_VT_CUSTOM_CODE);
                    if (field_offset == 0) return false;

                    offset_pos = op_table + field_offset;
                    offset_size = 4;
                }
            }
            break;

        default:
            return false;
    }

    if (offset_pos == 0 || offset_pos + offset_size > size) return false;

    // Mutate offset
    if (offset_size == 2) {
        // voffset (2 bytes)
        uint16_t current = read_u16_le(buf + offset_pos);
        int delta = ((rand() % 3) - 1) * 2;  // -2, 0, +2
        uint16_t new_val = current + delta;
        write_u16_le(buf + offset_pos, new_val);
    } else {
        // soffset or uoffset (4 bytes)
        uint32_t current = read_u32_le(buf + offset_pos);
        int delta = ((rand() % 3) - 1) * 4;  // -4, 0, +4
        uint32_t new_val = current + delta;

        // 새롭게 연산된 new_val offset이 파일 범위 내에 있는지 검증
        if (offset_pos + new_val < size) {
            write_u32_le(buf + offset_pos, new_val);
        } else {
            return false;
        }
    }

    return true;
}

// Mutation Strategy 4: Vector size manipulation
/* 
    Unsafe Mutation

    변이 대상 Vector:
    1. Model->signature_defs()->size() (==Vector<Offset<Signature>>)
    2. Model->metadata()->size() (==Vector<Offset<Metadata>>)
    3. Model->buffers()->size() (==Vector<Offset<Buffer>>)
    4. Model->subgraphs()->size() (==Vector<Offset<Subgraph>>)
    5. Model->operator_codes()->size() (==Vector<Offset<OperatorCode>>)

    6. Model->subgraphs()->Get(i)->tensors()->size() (==Vector<Offset<Tensor>>)
    
    * Vector 객체에 접근할 때도 유효한 주소인지 확인(연산)하면서 접근 필요.
*/
static bool mutate_vector_size_field(uint8_t* buf, size_t size) {
    ParsedInfo info;
    if (!parse_structure_info(buf, size, &info)) {
        return false;
    }

    int target = rand() % 6;
    uint32_t vec_offset = 0;
    uint32_t current_size = 0;

    switch (target) {
        case 0:
            vec_offset = info.signature_defs_vector_offset;
            current_size = info.num_signature_defs;
            break;
        case 1:
            vec_offset = info.metadata_vector_offset;
            current_size = info.num_metadata;
            break;
        case 2:
            vec_offset = info.buffers_vector_offset;
            current_size = info.num_buffers;
            break;
        case 3:
            vec_offset = info.subgraphs_vector_offset;
            current_size = info.num_subgraphs;
            break;
        case 4:
            vec_offset = info.operator_codes_vector_offset;
            current_size = info.num_operator_codes;
            break;
        case 5: // Subgraph->tensors() Vector
            if (info.num_subgraphs == 0) return false;
            {
                uint32_t idx = rand() % info.num_subgraphs;
                uint32_t sub_elem_offset_pos = info.subgraphs_vector_offset + 4 + idx * 4;

                if (sub_elem_offset_pos + 4 > size) return false;
                uint32_t sub_uoffset = read_u32_le(buf + sub_elem_offset_pos);
                // Subgraph 객체
                uint32_t sub_table = sub_elem_offset_pos + sub_uoffset;

                if (sub_table + 4 > size) return false;
                int32_t sub_vtable_soffset = -(int32_t)read_u32_le(buf + sub_table);
                uint32_t sub_vtable = sub_table + sub_vtable_soffset;

                if (sub_vtable + 4 > size) return false;

                // Get tensors vector offset
                if (sub_vtable + SUBGRAPH_VT_TENSORS + 2 > size) return false;
                uint16_t tensors_field_offset = read_u16_le(buf + sub_vtable + SUBGRAPH_VT_TENSORS);
                if (tensors_field_offset == 0) return false;

                uint32_t tensors_uoffset_pos = sub_table + tensors_field_offset;
                if (tensors_uoffset_pos + 4 > size) return false;

                uint32_t tensors_uoffset = read_u32_le(buf + tensors_uoffset_pos);
                vec_offset = tensors_uoffset_pos + tensors_uoffset;

                if (vec_offset + 4 > size) return false;
                current_size = read_u32_le(buf + vec_offset);
            }
            break;
    }

    if (vec_offset == 0) return false; //  "|| current_size == 0"은 제외. 없던 개수를 늘릴 수도, 음수로 만들어 볼 수도 있으니.
    if (vec_offset + 4 > size) return false;

    int delta = (rand() % 5) - 2;  // -2 ~ +2
    int32_t new_size = (int32_t)current_size + delta;

    if (new_size < 1) new_size = 0;
    if (new_size > 10000) new_size = 10000;

    write_u32_le(buf + vec_offset, (uint32_t)new_size);
    return true;
}

// Mutation Strategy 5: 임의 위치에 무작위 바이트 삽입 (구조 파괴)
/*
    Unsafe Mutation
    
    Model Table 이후에 1~16바이트의 바이트 삽입
    구조를 파괴하여 Edge case를 유도하려는 전략이기 때문에
    그 외의 위치는 상관 없음
*/
static bool mutate_insert_random_bytes(uint8_t* buf, size_t* size, size_t max_size) {
    if (*size + 16 > max_size) return false;
    if (*size <= 0x3C) return false;

    uint32_t insert_pos = 0x3C + (rand() % (*size - 0x3C));
    uint32_t insert_len = (rand() % 16) + 1; // 1~16 길이의 바이트

    if (*size + insert_len > max_size) return false;

    memmove(buf + insert_pos + insert_len, buf + insert_pos,
            *size - insert_pos);

    for (uint32_t i = 0; i < insert_len; i++) {
        buf[insert_pos + i] = rand() & 0xFF;
    }

    *size += insert_len;
    return true;
}

// AFL++ interface
custom_mutator_t* afl_custom_init(afl_state_t* afl, unsigned int seed) {
    srand(seed);

    custom_mutator_t* data = calloc(1, sizeof(custom_mutator_t));
    if (!data) return NULL;

    data->fuzz_buf_capacity = MAX_FILE;
    data->fuzz_buf = malloc(data->fuzz_buf_capacity);
    if (!data->fuzz_buf) {
        free(data);
        return NULL;
    }

    data->afl = afl;
    data->mutation_count = 0;
    data->safe_mutations = 0;
    data->unsafe_mutations = 0;

    return data;
}

size_t afl_custom_fuzz(custom_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

    // First few iterations: pass through unchanged (for dry run)
    if (data->mutation_count < 10) {
        if (buf_size > data->fuzz_buf_capacity) {
            buf_size = data->fuzz_buf_capacity;
        }
        memcpy(data->fuzz_buf, buf, buf_size);
        *out_buf = data->fuzz_buf;
        data->mutation_count++;
        return buf_size;
    }

    // Validate and fix if needed
    if (!is_valid_tflite(buf, buf_size)) {
        int prob = rand() % 100;
        if (prob < 90) {
            // Fix root offset and identifier
            memcpy(data->fuzz_buf, buf, buf_size);

            data->fuzz_buf[0] = 0x1C;
            data->fuzz_buf[1] = 0;
            data->fuzz_buf[2] = 0;
            data->fuzz_buf[3] = 0;

            data->fuzz_buf[4] = TFLITE_IDENTIFIER_0;
            data->fuzz_buf[5] = TFLITE_IDENTIFIER_1;
            data->fuzz_buf[6] = TFLITE_IDENTIFIER_2;
            data->fuzz_buf[7] = TFLITE_IDENTIFIER_3;

            buf = data->fuzz_buf;
        } else {
            // Pass through unchanged (10%)
            memcpy(data->fuzz_buf, buf, buf_size);
            *out_buf = data->fuzz_buf;
            return buf_size;
        }
    }

    // Copy to working buffer
    if (buf_size > data->fuzz_buf_capacity) {
        buf_size = data->fuzz_buf_capacity;
    }
    memcpy(data->fuzz_buf, buf, buf_size);

    size_t new_size = buf_size;
    bool mutation_applied = false;

    data->mutation_count++;

    // Select strategy
    float strategy_roll = (float)rand() / RAND_MAX;

    if (strategy_roll < SAFE_MUTATION_THRESHOLD) {
        // 90%: Safe mutation
        mutation_applied = mutate_randomizable_field(data->fuzz_buf, new_size);
        if (mutation_applied) {
            data->safe_mutations++;
        }
    } else {
        // 10%: Unsafe mutation
        int risky_strategy = rand() % 4;
        switch (risky_strategy) {
            case 0:
                mutation_applied = mutate_vtable_field(data->fuzz_buf, new_size);
                break;
            case 1:
                mutation_applied = mutate_uoffset_field(data->fuzz_buf, new_size);
                break;
            case 2:
                mutation_applied = mutate_vector_size_field(data->fuzz_buf, new_size);
                break;
            case 3:
                mutation_applied = mutate_insert_random_bytes(data->fuzz_buf, &new_size, max_size);
                break;
        }
        if (mutation_applied) {
            data->unsafe_mutations++;
        }
    }

    // Mutation 실패 시, 단순 bit flip 수행
    if (!mutation_applied && new_size > 0x3C) {
        uint32_t pos = 0x3C + (rand() % (new_size - 0x3C));
        data->fuzz_buf[pos] ^= (1 << (rand() % 8));
        data->unsafe_mutations++;
    }

    // 10000 단위마다 통계 출력
    if (data->mutation_count % 10000 == 0) {
        fprintf(stderr,
                "[TFLite Mutator] Total: %lu, Safe: %lu (%.1f%%), Unsafe: %lu (%.1f%%)\n",
                data->mutation_count,
                data->safe_mutations,
                100.0 * data->safe_mutations / data->mutation_count,
                data->unsafe_mutations,
                100.0 * data->unsafe_mutations / data->mutation_count);
    }

    *out_buf = data->fuzz_buf;
    return new_size;
}

void afl_custom_deinit(custom_mutator_t *data) {
    if (data) {
        fprintf(stderr,
                "[TFLite Mutator] Final - Total: %lu, Safe: %lu, Unsafe: %lu\n",
                data->mutation_count, data->safe_mutations, data->unsafe_mutations);

        if (data->fuzz_buf) {
            free(data->fuzz_buf);
        }
        free(data);
    }
}

