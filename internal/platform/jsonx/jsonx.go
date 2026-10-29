// Package jsonx serializa JSON com a mesma forma do JSON.stringify do JavaScript.
//
// O pacote tem dois modos:
//
//   - Canonical ordena as chaves em todos os níveis. Dois valores iguais produzem
//     os mesmos bytes, o que permite assinar e reverificar um objeto relido do disco.
//   - Insertion preserva a ordem de inserção. Use este modo para os hashes de
//     instantâneo e de leis, que precisam reproduzir JSON.stringify de um objeto.
//
// Diferenças em relação ao encoding/json de Go, tratadas aqui:
//
//   - Não escapamos HTML (<, > e &), como o JSON.stringify.
//   - Não escapamos U+2028 e U+2029, como o JSON.stringify.
//   - A forma dos números é a do JavaScript, não a de strconv 'g'.
//   - Chaves que são índices de array vêm primeiro, em ordem numérica, no modo
//     de inserção.
//   - O padrão de escape de controle e de aspas é o mesmo do JSON.stringify.
//
// Um substituto isolado não existe em string de Go: bytes UTF-8 inválidos viram
// U+FFFD, como no encoding/json. A chave de objeto é sempre uma string.
package jsonx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

// Field é um par chave/valor de um objeto ordenado.
type Field struct {
	Key   string
	Value any
}

// Fields é uma lista de campos na ordem em que devem ser emitidos.
type Fields []Field

// Object é um objeto JSON que guarda a ordem de inserção.
//
// Use Set para inserir ou substituir um campo. Substituir um campo mantém a
// posição original, como em um objeto JavaScript.
type Object struct {
	fields []Field
	index  map[string]int
}

// NewObject cria um objeto vazio.
func NewObject() *Object {
	return &Object{index: make(map[string]int)}
}

// Set insere ou substitui um campo e devolve o próprio objeto.
func (o *Object) Set(key string, value any) *Object {
	if o.index == nil {
		o.index = make(map[string]int, len(o.fields)+1)
		for i := range o.fields {
			o.index[o.fields[i].Key] = i
		}
	}
	if i, ok := o.index[key]; ok {
		o.fields[i].Value = value
		return o
	}
	o.index[key] = len(o.fields)
	o.fields = append(o.fields, Field{Key: key, Value: value})
	return o
}

// Get devolve o valor de um campo.
func (o *Object) Get(key string) (any, bool) {
	i, ok := o.index[key]
	if !ok {
		return nil, false
	}
	return o.fields[i].Value, true
}

// Len devolve o número de campos.
func (o *Object) Len() int {
	if o == nil {
		return 0
	}
	return len(o.fields)
}

// SHA256Hex devolve o SHA-256 de data em hexadecimal minúsculo.
func SHA256Hex(data []byte) string {
	sum := SHA256Bytes(data)
	return hex.EncodeToString(sum[:])
}

// SHA256Bytes devolve o SHA-256 de data em bytes.
func SHA256Bytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// Canonical devolve o JSON com as chaves ordenadas em todos os níveis.
func Canonical(v any) ([]byte, error) {
	return encodeTop(v, modeCanonical)
}

// Insertion devolve o JSON preservando a ordem de inserção.
//
// Aceita *Object, Object, Fields e qualquer valor de Go. Uma mapa de Go não
// guarda ordem: as chaves não numéricas saem em ordem lexicográfica.
// json.RawMessage e []byte passados no topo são lidos como documento JSON e
// reemitidos na ordem do documento. Um string comum continua sendo um string
// JSON.
func Insertion(v any) ([]byte, error) {
	return encodeTop(v, modeInsertion)
}

type mode int

const (
	modeCanonical mode = iota
	modeInsertion
)

func encodeTop(v any, m mode) ([]byte, error) {
	if m == modeInsertion {
		switch raw := v.(type) {
		case json.RawMessage:
			decoded, err := decodeOrdered(raw)
			if err != nil {
				return nil, err
			}
			v = decoded
		case []byte:
			decoded, err := decodeOrdered(raw)
			if err != nil {
				return nil, err
			}
			v = decoded
		}
	}
	var buf bytes.Buffer
	if err := encode(&buf, reflect.ValueOf(v), m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var errUnsupported = errors.New("jsonx: tipo não suportado")

func encode(buf *bytes.Buffer, v reflect.Value, m mode) error {
	for v.IsValid() && v.Kind() == reflect.Interface {
		if v.IsNil() {
			buf.WriteString("null")
			return nil
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		buf.WriteString("null")
		return nil
	}

	if v.CanInterface() {
		switch value := v.Interface().(type) {
		case *Object:
			if value == nil {
				buf.WriteString("null")
				return nil
			}
			return encodeObjectFields(buf, value.fields, m)
		case Object:
			return encodeObjectFields(buf, value.fields, m)
		case Fields:
			return encodeObjectFields(buf, value, m)
		case json.Number:
			return writeJSONNumber(buf, string(value))
		}
	}

	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			buf.WriteString("null")
			return nil
		}
		return encode(buf, v.Elem(), m)
	}

	switch v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case reflect.String:
		writeJSONString(buf, v.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		buf.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		buf.WriteString(strconv.FormatUint(v.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		buf.WriteString(formatNumber(v.Float()))
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			buf.WriteString("null")
			return nil
		}
		if err := encodeArray(buf, v, m); err != nil {
			return err
		}
	case reflect.Map:
		if v.IsNil() {
			buf.WriteString("null")
			return nil
		}
		return encodeMap(buf, v, m)
	case reflect.Struct:
		return encodeStruct(buf, v, m)
	default:
		return fmt.Errorf("%w: %s", errUnsupported, v.Type())
	}
	return nil
}

func encodeArray(buf *bytes.Buffer, v reflect.Value, m mode) error {
	buf.WriteByte('[')
	for i := range v.Len() {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := encode(buf, v.Index(i), m); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

func encodeMap(buf *bytes.Buffer, v reflect.Value, m mode) error {
	if v.Type().Key().Kind() != reflect.String {
		return fmt.Errorf("%w: map com chave %s", errUnsupported, v.Type().Key())
	}
	type entry struct {
		key   string
		value reflect.Value
	}
	entries := make([]entry, 0, v.Len())
	iter := v.MapRange()
	for iter.Next() {
		entries = append(entries, entry{key: iter.Key().String(), value: iter.Value()})
	}
	sort.Slice(entries, func(i, j int) bool { return lessUTF16(entries[i].key, entries[j].key) })
	return writeObject(buf, len(entries), func(i int) (string, reflect.Value) {
		return entries[i].key, entries[i].value
	}, m)
}

func encodeObjectFields(buf *bytes.Buffer, fields []Field, m mode) error {
	order := make([]int, len(fields))
	for i := range order {
		order[i] = i
	}
	if m == modeInsertion {
		order = insertionOrder(fields, order)
	} else {
		sort.SliceStable(order, func(i, j int) bool {
			return lessUTF16(fields[order[i]].Key, fields[order[j]].Key)
		})
	}
	buf.WriteByte('{')
	for position, i := range order {
		if position > 0 {
			buf.WriteByte(',')
		}
		writeJSONString(buf, fields[i].Key)
		buf.WriteByte(':')
		if err := encode(buf, reflect.ValueOf(fields[i].Value), m); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// writeObject emite um objeto a partir de chaves já ordenadas. get devolve a
// chave e o valor na posição i. No modo de inserção, as chaves que são índices
// de array vêm primeiro, em ordem numérica, como em um objeto JavaScript.
func writeObject(buf *bytes.Buffer, n int, get func(i int) (string, reflect.Value), m mode) error {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	if m == modeInsertion {
		indices := make([]int, 0, n)
		rest := make([]int, 0, n)
		for i := range order {
			key, _ := get(i)
			if _, ok := arrayIndex(key); ok {
				indices = append(indices, i)
			} else {
				rest = append(rest, i)
			}
		}
		sort.SliceStable(indices, func(a, b int) bool {
			ka, _ := get(indices[a])
			kb, _ := get(indices[b])
			na, _ := arrayIndex(ka)
			nb, _ := arrayIndex(kb)
			return na < nb
		})
		order = append(indices, rest...)
	}
	buf.WriteByte('{')
	for position, i := range order {
		if position > 0 {
			buf.WriteByte(',')
		}
		key, value := get(i)
		writeJSONString(buf, key)
		buf.WriteByte(':')
		if err := encode(buf, value, m); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// insertionOrder reordena posições de fields: índices de array primeiro, em
// ordem numérica; os demais mantêm a ordem recebida.
func insertionOrder(fields []Field, order []int) []int {
	indices := make([]int, 0, len(order))
	rest := make([]int, 0, len(order))
	for _, i := range order {
		if _, ok := arrayIndex(fields[i].Key); ok {
			indices = append(indices, i)
		} else {
			rest = append(rest, i)
		}
	}
	sort.SliceStable(indices, func(a, b int) bool {
		na, _ := arrayIndex(fields[indices[a]].Key)
		nb, _ := arrayIndex(fields[indices[b]].Key)
		return na < nb
	})
	return append(indices, rest...)
}

// arrayIndex reconhece a chave de um índice de array JavaScript: um inteiro
// decimal canônico entre 0 e 2^32-2.
func arrayIndex(key string) (uint64, bool) {
	if key == "" || len(key) > 10 {
		return 0, false
	}
	if key != "0" && key[0] == '0' {
		return 0, false
	}
	for i := range len(key) {
		if key[i] < '0' || key[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(key, 10, 64)
	if err != nil || n > 4294967294 {
		return 0, false
	}
	return n, true
}

// lessUTF16 compara chaves pela unidade de código UTF-16, como o sort() do
// JavaScript. Difere da comparação de bytes para caracteres fora do BMP.
func lessUTF16(a, b string) bool {
	au := utf16.Encode([]rune(a))
	bu := utf16.Encode([]rune(b))
	for i := 0; i < len(au) && i < len(bu); i++ {
		if au[i] != bu[i] {
			return au[i] < bu[i]
		}
	}
	return len(au) < len(bu)
}

// writeJSONString escreve um string JSON com o mesmo escape do JSON.stringify:
// aspas, barra invertida e os controles C0; nada mais é escapado.
func writeJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				buf.WriteString(`\"`)
			case '\\':
				buf.WriteString(`\\`)
			case '\b':
				buf.WriteString(`\b`)
			case '\f':
				buf.WriteString(`\f`)
			case '\n':
				buf.WriteString(`\n`)
			case '\r':
				buf.WriteString(`\r`)
			case '\t':
				buf.WriteString(`\t`)
			default:
				if c < 0x20 {
					buf.WriteString(`\u00`)
					buf.WriteByte(hexDigits[c>>4])
					buf.WriteByte(hexDigits[c&0xf])
				} else {
					buf.WriteByte(c)
				}
			}
			i++
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		if size == 1 {
			// Byte inválido: vira U+FFFD, como no encoding/json.
			buf.WriteString("\uFFFD")
			i++
			continue
		}
		_, _ = buf.WriteString(s[i : i+size])
		i += size
	}
	buf.WriteByte('"')
}

const hexDigits = "0123456789abcdef"

// formatNumber escreve um float64 na forma do Number::toString do JavaScript.
// NaN e infinito não têm representação JSON: o JSON.stringify os escreve como
// null.
func formatNumber(f float64) string {
	if f != f || f > 1.7976931348623157e308 || f < -1.7976931348623157e308 {
		return "null"
	}
	if f == 0 {
		// Cobre -0: o JSON.stringify escreve "0".
		return "0"
	}
	negative := f < 0
	if negative {
		f = -f
	}

	s := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exponent, _ := strings.Cut(s, "e")
	exp, err := strconv.Atoi(exponent)
	if err != nil {
		return "null"
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	k := len(digits)
	n := exp + 1

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		sign := "+"
		if e < 0 {
			sign = "-"
			e = -e
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(e)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(e)
		}
	}
	if negative {
		return "-" + out
	}
	return out
}

func writeJSONNumber(buf *bytes.Buffer, number string) error {
	f, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return fmt.Errorf("jsonx: número inválido %q: %w", number, err)
	}
	buf.WriteString(formatNumber(f))
	return nil
}

// ── Decodificação com ordem ────────────────────────────────────────

// decodeOrdered lê um documento JSON preservando a ordem dos campos. Números
// ficam como json.Number e são reescritos na forma do JavaScript na saída.
func decodeOrdered(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := readTokenValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("jsonx: conteúdo depois do documento: %w", err)
	}
	return value, nil
}

func readTokenValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := NewObject()
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("jsonx: chave de objeto não é string: %v", keyToken)
			}
			value, err := readTokenValue(dec)
			if err != nil {
				return nil, err
			}
			object.Set(key, value)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for dec.More() {
			value, err := readTokenValue(dec)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return array, nil
	default:
		return nil, fmt.Errorf("jsonx: delimitador inesperado %q", delim)
	}
}

// ── Structs ────────────────────────────────────────────────────────

type structField struct {
	index     []int
	name      string
	omitEmpty bool
}

var structCache sync.Map // reflect.Type → []structField

func fieldsOf(t reflect.Type) []structField {
	if cached, ok := structCache.Load(t); ok {
		return cached.([]structField)
	}
	fields := collectStructFields(t, nil)
	structCache.Store(t, fields)
	return fields
}

func collectStructFields(t reflect.Type, prefix []int) []structField {
	var fields []structField
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		index := append(append([]int(nil), prefix...), i)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("json")
		name, options := tag, ""
		if comma := strings.IndexByte(tag, ','); comma >= 0 {
			name, options = tag[:comma], tag[comma+1:]
		}
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			embedded := field.Type
			if embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct && embedded != reflect.TypeOf(Object{}) && embedded != reflect.TypeOf(Field{}) {
				fields = append(fields, collectStructFields(embedded, index)...)
				continue
			}
		}
		if name == "" {
			name = field.Name
		}
		fields = append(fields, structField{
			index:     index,
			name:      name,
			omitEmpty: hasOption(options, "omitempty"),
		})
	}
	return fields
}

func hasOption(options, option string) bool {
	for options != "" {
		var current string
		current, options, _ = strings.Cut(options, ",")
		if current == option {
			return true
		}
	}
	return false
}

func encodeStruct(buf *bytes.Buffer, v reflect.Value, m mode) error {
	fields := fieldsOf(v.Type())
	type entry struct {
		name  string
		value reflect.Value
	}
	entries := make([]entry, 0, len(fields))
	for _, field := range fields {
		value := v.FieldByIndex(field.index)
		if field.omitEmpty && isEmptyValue(value) {
			continue
		}
		entries = append(entries, entry{name: field.name, value: value})
	}
	order := make([]int, len(entries))
	for i := range order {
		order[i] = i
	}
	if m == modeCanonical {
		sort.SliceStable(order, func(i, j int) bool {
			return lessUTF16(entries[order[i]].name, entries[order[j]].name)
		})
	}
	buf.WriteByte('{')
	for position, i := range order {
		if position > 0 {
			buf.WriteByte(',')
		}
		writeJSONString(buf, entries[i].name)
		buf.WriteByte(':')
		if err := encode(buf, entries[i].value, m); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	}
	return false
}
