import Chio.Json.Canonical

set_option autoImplicit false

namespace Chio.Json.Fixtures

def corpusCaseCount : Nat := 16

def object_key_sorting : JValue := .obj (.cons ([.literal 97 (by decide)]) (.int ({ negative := false, digits := [({ val := 2, isLt := by decide } : Fin 10)], valid := by decide })) (.cons ([.literal 109 (by decide)]) (.int ({ negative := false, digits := [({ val := 3, isLt := by decide } : Fin 10)], valid := by decide })) (.cons ([.literal 122 (by decide)]) (.int ({ negative := false, digits := [({ val := 1, isLt := by decide } : Fin 10)], valid := by decide })) (.nil))))
#guard canonical object_key_sorting == [123, 34, 97, 34, 58, 50, 44, 34, 109, 34, 58, 51, 44, 34, 122, 34, 58, 49, 125]

def nested_structures : JValue := .obj (.cons ([.literal 101 (by decide), .literal 110 (by decide), .literal 97 (by decide), .literal 98 (by decide), .literal 108 (by decide), .literal 101 (by decide), .literal 100 (by decide)]) (.bool true) (.cons ([.literal 112 (by decide), .literal 97 (by decide), .literal 114 (by decide), .literal 97 (by decide), .literal 109 (by decide), .literal 115 (by decide)]) (.obj (.cons ([.literal 102 (by decide), .literal 108 (by decide), .literal 97 (by decide), .literal 103 (by decide), .literal 115 (by decide)]) (.arr (.cons (.str ([.literal 114 (by decide), .literal 101 (by decide), .literal 97 (by decide), .literal 100 (by decide)])) (.cons (.str ([.literal 116 (by decide), .literal 101 (by decide), .literal 120 (by decide), .literal 116 (by decide)])) (.nil)))) (.cons ([.literal 112 (by decide), .literal 97 (by decide), .literal 116 (by decide), .literal 104 (by decide)]) (.str ([.literal 47 (by decide), .literal 116 (by decide), .literal 109 (by decide), .literal 112 (by decide), .literal 47 (by decide), .literal 100 (by decide), .literal 101 (by decide), .literal 109 (by decide), .literal 111 (by decide)])) (.nil)))) (.cons ([.literal 116 (by decide), .literal 111 (by decide), .literal 111 (by decide), .literal 108 (by decide)]) (.str ([.literal 114 (by decide), .literal 101 (by decide), .literal 97 (by decide), .literal 100 (by decide)])) (.nil))))
#guard canonical nested_structures == [123, 34, 101, 110, 97, 98, 108, 101, 100, 34, 58, 116, 114, 117, 101, 44, 34, 112, 97, 114, 97, 109, 115, 34, 58, 123, 34, 102, 108, 97, 103, 115, 34, 58, 91, 34, 114, 101, 97, 100, 34, 44, 34, 116, 101, 120, 116, 34, 93, 44, 34, 112, 97, 116, 104, 34, 58, 34, 47, 116, 109, 112, 47, 100, 101, 109, 111, 34, 125, 44, 34, 116, 111, 111, 108, 34, 58, 34, 114, 101, 97, 100, 34, 125]

def utf16_key_ordering : JValue := .obj (.cons ([.literal 65536 (by decide)]) (.int ({ negative := false, digits := [({ val := 2, isLt := by decide } : Fin 10)], valid := by decide })) (.cons ([.literal 57344 (by decide)]) (.int ({ negative := false, digits := [({ val := 1, isLt := by decide } : Fin 10)], valid := by decide })) (.nil)))
#guard canonical utf16_key_ordering == [123, 34, 240, 144, 128, 128, 34, 58, 50, 44, 34, 238, 128, 128, 34, 58, 49, 125]

def string_escaping : JValue := .obj (.cons ([.literal 116 (by decide), .literal 101 (by decide), .literal 120 (by decide), .literal 116 (by decide)]) (.str ([.literal 108 (by decide), .literal 105 (by decide), .literal 110 (by decide), .literal 101 (by decide), .lineFeed, .quote, .literal 113 (by decide), .literal 117 (by decide), .literal 111 (by decide), .literal 116 (by decide), .literal 101 (by decide), .literal 100 (by decide), .quote, .reverseSolidus, .literal 112 (by decide), .literal 97 (by decide), .literal 116 (by decide), .literal 104 (by decide)])) (.nil))
#guard canonical string_escaping == [123, 34, 116, 101, 120, 116, 34, 58, 34, 108, 105, 110, 101, 92, 110, 92, 34, 113, 117, 111, 116, 101, 100, 92, 34, 92, 92, 112, 97, 116, 104, 34, 125]

def u007f_escape : JValue := .str ([.literal 127 (by decide)])
#guard canonical u007f_escape == [34, 127, 34]

def u001f_escape : JValue := .str ([.control ({ val := 1, isLt := by decide } : Fin 16) ({ val := 15, isLt := by decide } : Fin 16) (by decide)])
#guard canonical u001f_escape == [34, 92, 117, 48, 48, 49, 102, 34]

def u009f_escape : JValue := .str ([.literal 159 (by decide)])
#guard canonical u009f_escape == [34, 194, 159, 34]

def empty_object : JValue := .obj (.nil)
#guard canonical empty_object == [123, 125]

def empty_array : JValue := .arr (.nil)
#guard canonical empty_array == [91, 93]

def empty_string_value : JValue := .obj (.cons ([.literal 107 (by decide)]) (.str ([])) (.nil))
#guard canonical empty_string_value == [123, 34, 107, 34, 58, 34, 34, 125]

def bare_null_literal : JValue := .null
#guard canonical bare_null_literal == [110, 117, 108, 108]

def boolean_and_null_array : JValue := .arr (.cons (.bool true) (.cons (.bool false) (.cons (.null) (.nil))))
#guard canonical boolean_and_null_array == [91, 116, 114, 117, 101, 44, 102, 97, 108, 115, 101, 44, 110, 117, 108, 108, 93]

def i64_signed_boundaries : JValue := .obj (.cons ([.literal 109 (by decide), .literal 97 (by decide), .literal 120 (by decide), .literal 95 (by decide), .literal 105 (by decide), .literal 54 (by decide), .literal 52 (by decide)]) (.int ({ negative := false, digits := [({ val := 9, isLt := by decide } : Fin 10), ({ val := 2, isLt := by decide } : Fin 10), ({ val := 2, isLt := by decide } : Fin 10), ({ val := 3, isLt := by decide } : Fin 10), ({ val := 3, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 2, isLt := by decide } : Fin 10), ({ val := 0, isLt := by decide } : Fin 10), ({ val := 3, isLt := by decide } : Fin 10), ({ val := 6, isLt := by decide } : Fin 10), ({ val := 8, isLt := by decide } : Fin 10), ({ val := 5, isLt := by decide } : Fin 10), ({ val := 4, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 5, isLt := by decide } : Fin 10), ({ val := 8, isLt := by decide } : Fin 10), ({ val := 0, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10)], valid := by decide })) (.cons ([.literal 109 (by decide), .literal 105 (by decide), .literal 110 (by decide), .literal 95 (by decide), .literal 105 (by decide), .literal 54 (by decide), .literal 52 (by decide)]) (.int ({ negative := true, digits := [({ val := 9, isLt := by decide } : Fin 10), ({ val := 2, isLt := by decide } : Fin 10), ({ val := 2, isLt := by decide } : Fin 10), ({ val := 3, isLt := by decide } : Fin 10), ({ val := 3, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 2, isLt := by decide } : Fin 10), ({ val := 0, isLt := by decide } : Fin 10), ({ val := 3, isLt := by decide } : Fin 10), ({ val := 6, isLt := by decide } : Fin 10), ({ val := 8, isLt := by decide } : Fin 10), ({ val := 5, isLt := by decide } : Fin 10), ({ val := 4, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 5, isLt := by decide } : Fin 10), ({ val := 8, isLt := by decide } : Fin 10), ({ val := 0, isLt := by decide } : Fin 10), ({ val := 8, isLt := by decide } : Fin 10)], valid := by decide })) (.nil)))
#guard canonical i64_signed_boundaries == [123, 34, 109, 97, 120, 95, 105, 54, 52, 34, 58, 57, 50, 50, 51, 51, 55, 50, 48, 51, 54, 56, 53, 52, 55, 55, 53, 56, 48, 55, 44, 34, 109, 105, 110, 95, 105, 54, 52, 34, 58, 45, 57, 50, 50, 51, 51, 55, 50, 48, 51, 54, 56, 53, 52, 55, 55, 53, 56, 48, 56, 125]

def u64_above_i64_max : JValue := .obj (.cons ([.literal 109 (by decide), .literal 97 (by decide), .literal 120 (by decide), .literal 95 (by decide), .literal 117 (by decide), .literal 54 (by decide), .literal 52 (by decide)]) (.int ({ negative := false, digits := [({ val := 1, isLt := by decide } : Fin 10), ({ val := 8, isLt := by decide } : Fin 10), ({ val := 4, isLt := by decide } : Fin 10), ({ val := 4, isLt := by decide } : Fin 10), ({ val := 6, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 4, isLt := by decide } : Fin 10), ({ val := 4, isLt := by decide } : Fin 10), ({ val := 0, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 3, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 0, isLt := by decide } : Fin 10), ({ val := 9, isLt := by decide } : Fin 10), ({ val := 5, isLt := by decide } : Fin 10), ({ val := 5, isLt := by decide } : Fin 10), ({ val := 1, isLt := by decide } : Fin 10), ({ val := 6, isLt := by decide } : Fin 10), ({ val := 1, isLt := by decide } : Fin 10), ({ val := 5, isLt := by decide } : Fin 10)], valid := by decide })) (.nil))
#guard canonical u64_above_i64_max == [123, 34, 109, 97, 120, 95, 117, 54, 52, 34, 58, 49, 56, 52, 52, 54, 55, 52, 52, 48, 55, 51, 55, 48, 57, 53, 53, 49, 54, 49, 53, 125]

def integer_above_double_precision : JValue := .obj (.cons ([.literal 116 (by decide), .literal 119 (by decide), .literal 111 (by decide), .literal 95 (by decide), .literal 116 (by decide), .literal 111 (by decide), .literal 95 (by decide), .literal 53 (by decide), .literal 51 (by decide), .literal 95 (by decide), .literal 112 (by decide), .literal 108 (by decide), .literal 117 (by decide), .literal 115 (by decide), .literal 95 (by decide), .literal 111 (by decide), .literal 110 (by decide), .literal 101 (by decide)]) (.int ({ negative := false, digits := [({ val := 9, isLt := by decide } : Fin 10), ({ val := 0, isLt := by decide } : Fin 10), ({ val := 0, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 1, isLt := by decide } : Fin 10), ({ val := 9, isLt := by decide } : Fin 10), ({ val := 9, isLt := by decide } : Fin 10), ({ val := 2, isLt := by decide } : Fin 10), ({ val := 5, isLt := by decide } : Fin 10), ({ val := 4, isLt := by decide } : Fin 10), ({ val := 7, isLt := by decide } : Fin 10), ({ val := 4, isLt := by decide } : Fin 10), ({ val := 0, isLt := by decide } : Fin 10), ({ val := 9, isLt := by decide } : Fin 10), ({ val := 9, isLt := by decide } : Fin 10), ({ val := 3, isLt := by decide } : Fin 10)], valid := by decide })) (.nil))
#guard canonical integer_above_double_precision == [123, 34, 116, 119, 111, 95, 116, 111, 95, 53, 51, 95, 112, 108, 117, 115, 95, 111, 110, 101, 34, 58, 57, 48, 48, 55, 49, 57, 57, 50, 53, 52, 55, 52, 48, 57, 57, 51, 125]

def supplementary_plane_key_sort : JValue := .obj (.cons ([.literal 97 (by decide)]) (.int ({ negative := false, digits := [({ val := 1, isLt := by decide } : Fin 10)], valid := by decide })) (.cons ([.literal 128512 (by decide)]) (.int ({ negative := false, digits := [({ val := 1, isLt := by decide } : Fin 10)], valid := by decide })) (.nil)))
#guard canonical supplementary_plane_key_sort == [123, 34, 97, 34, 58, 49, 44, 34, 240, 159, 152, 128, 34, 58, 49, 125]

end Chio.Json.Fixtures
