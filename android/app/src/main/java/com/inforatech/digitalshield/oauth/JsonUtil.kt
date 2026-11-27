package com.inforatech.digitalshield.oauth

/**
 * Lightweight, dependency-free JSON parser and string escaper for Android & JVM unit tests.
 */
internal object JsonUtil {
    fun escapeString(value: String): String {
        val sb = StringBuilder(value.length + 16)
        sb.append('"')
        for (ch in value) {
            when (ch) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> sb.append(ch)
            }
        }
        sb.append('"')
        return sb.toString()
    }

    fun objectJson(vararg pairs: Pair<String, String>): String {
        return pairs.joinToString(prefix = "{", postfix = "}", separator = ",") { (k, v) ->
            "${escapeString(k)}:${escapeString(v)}"
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun parseObject(raw: String): Map<String, Any?> {
        return Parser(raw).parseValue() as? Map<String, Any?>
            ?: throw IllegalArgumentException("Expected JSON object")
    }

    @Suppress("UNCHECKED_CAST")
    fun parseArray(raw: String): List<Any?> {
        return Parser(raw).parseValue() as? List<Any?>
            ?: throw IllegalArgumentException("Expected JSON array")
    }

    private class Parser(private val src: String) {
        private var pos = 0

        fun parseValue(): Any? {
            skipWhitespace()
            if (pos >= src.length) throw IllegalArgumentException("Unexpected end of JSON")
            return when (src[pos]) {
                '{' -> parseObj()
                '[' -> parseArr()
                '"' -> parseStr()
                't' -> { expect("true"); true }
                'f' -> { expect("false"); false }
                'n' -> { expect("null"); null }
                '-', in '0'..'9' -> parseNum()
                else -> throw IllegalArgumentException("Unexpected char at $pos")
            }
        }

        private fun parseObj(): Map<String, Any?> {
            pos++ // {
            val map = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (pos < src.length && src[pos] == '}') {
                pos++
                return map
            }
            while (pos < src.length) {
                skipWhitespace()
                val key = parseStr()
                skipWhitespace()
                if (pos >= src.length || src[pos] != ':') throw IllegalArgumentException("Expected ':'")
                pos++
                map[key] = parseValue()
                skipWhitespace()
                if (pos < src.length && src[pos] == ',') {
                    pos++
                    continue
                }
                if (pos < src.length && src[pos] == '}') {
                    pos++
                    return map
                }
                throw IllegalArgumentException("Expected ',' or '}'")
            }
            throw IllegalArgumentException("Unterminated JSON object")
        }

        private fun parseArr(): List<Any?> {
            pos++ // [
            val list = ArrayList<Any?>()
            skipWhitespace()
            if (pos < src.length && src[pos] == ']') {
                pos++
                return list
            }
            while (pos < src.length) {
                list.add(parseValue())
                skipWhitespace()
                if (pos < src.length && src[pos] == ',') {
                    pos++
                    continue
                }
                if (pos < src.length && src[pos] == ']') {
                    pos++
                    return list
                }
                throw IllegalArgumentException("Expected ',' or ']'")
            }
            throw IllegalArgumentException("Unterminated JSON array")
        }

        private fun parseStr(): String {
            if (pos >= src.length || src[pos] != '"') throw IllegalArgumentException("Expected '\"'")
            pos++
            val sb = StringBuilder()
            while (pos < src.length) {
                val ch = src[pos++]
                if (ch == '"') return sb.toString()
                if (ch == '\\' && pos < src.length) {
                    when (val esc = src[pos++]) {
                        '"', '\\', '/' -> sb.append(esc)
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val hex = src.substring(pos, pos + 4)
                            sb.append(hex.toInt(16).toChar())
                            pos += 4
                        }
                        else -> sb.append(esc)
                    }
                } else {
                    sb.append(ch)
                }
            }
            throw IllegalArgumentException("Unterminated string")
        }

        private fun parseNum(): Number {
            val start = pos
            while (pos < src.length && src[pos] in "-0123456789.eE+") pos++
            val raw = src.substring(start, pos)
            return if (raw.contains('.') || raw.contains('e') || raw.contains('E')) raw.toDouble() else raw.toLong()
        }

        private fun expect(literal: String) {
            if (!src.startsWith(literal, pos)) throw IllegalArgumentException("Expected $literal")
            pos += literal.length
        }

        private fun skipWhitespace() {
            while (pos < src.length && src[pos].isWhitespace()) pos++
        }
    }
}
