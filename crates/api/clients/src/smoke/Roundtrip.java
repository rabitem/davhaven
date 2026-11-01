import davhaven.client.ApiClient;
import davhaven.client.model.EventView;
import davhaven.client.model.ProblemDetails;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Reads documents as the server sends them with the generated Java model and writes them again: the two documents
 * must be equal. It covers what trips generated clients up: enumerations, nullable members, the alarm trigger (a
 * tagged union) and the time zone fields, in an event and in a problem document (whose code is an enumeration that
 * the API documents as growing).
 *
 * <p>It also reads the same documents with values that a later version of the API may send, an enumeration value
 * that this client does not know, and requires the generated model to read them instead of throwing (the
 * compatibility policy of {@code docs/api.md}).
 */
public final class Roundtrip {
    /** What OpenAPI Generator writes for an enumeration value the model does not know. */
    private static final String UNKNOWN = "unknown_default_open_api";

    private Roundtrip() {}

    /** Collects the places where the two documents differ, as "path: expected, actual". */
    private static void differences(
            String path, JsonNode expected, JsonNode actual, Set<String> unknown, List<String> found) {
        if (unknown.contains(path)) {
            // A value this client does not know: the model writes its placeholder, and nothing else about the
            // document may have changed.
            if (actual == null || !actual.isTextual() || !UNKNOWN.equals(actual.asText())) {
                found.add(path + ": " + UNKNOWN + ", " + actual);
            }
            return;
        }
        if (expected == null
                && actual != null
                && actual.isArray()
                && actual.isEmpty()
                && (path.endsWith("/rdates") || path.endsWith("/exdates"))) {
            // The generated model starts the lists of a recurrence empty and writes them; for the server an empty
            // list of extra or excluded instances is the same as none. (The lists that replace stored values,
            // attendees, alarms and categories, stay absent until the client sets them, and must roundtrip.)
            return;
        }
        if (expected == null || actual == null) {
            found.add(path + ": " + expected + ", " + actual);
        } else if (expected.isObject() && actual.isObject()) {
            TreeSet<String> names = new TreeSet<>();
            expected.fieldNames().forEachRemaining(names::add);
            actual.fieldNames().forEachRemaining(names::add);
            for (String name : names) {
                differences(path + "/" + name, expected.get(name), actual.get(name), unknown, found);
            }
        } else if (expected.isArray() && actual.isArray() && expected.size() == actual.size()) {
            for (int index = 0; index < expected.size(); index++) {
                differences(path + "/" + index, expected.get(index), actual.get(index), unknown, found);
            }
        } else if (!expected.equals(actual)) {
            found.add(path + ": " + expected + ", " + actual);
        }
    }

    /** Reads {@code text} with {@code type}, writes it again and returns the differences. */
    private static <T> List<String> through(ObjectMapper mapper, String text, Class<T> type, Set<String> unknown)
            throws Exception {
        T model = mapper.readValue(text, type);
        List<String> found = new ArrayList<>();
        differences("", mapper.readTree(text), mapper.readTree(mapper.writeValueAsString(model)), unknown, found);
        return found;
    }

    private static boolean report(String what, List<String> found) {
        if (found.isEmpty()) {
            System.out.println(what);
            return true;
        }
        System.err.println("FAILED: " + what + " (path: expected, actual)");
        found.forEach(line -> System.err.println("  " + line));
        return false;
    }

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ApiClient().getObjectMapper();
        String event = Files.readString(Path.of(args[0]));
        String problem = Files.readString(Path.of(args[1]));
        String write = Files.readString(Path.of(args[2]));
        boolean ok = true;

        ok &= report(
                "the generated Java model reads and writes the event unchanged",
                through(mapper, event, EventView.class, Set.of()));
        ok &= report(
                "the generated Java model reads and writes the problem unchanged",
                through(mapper, problem, ProblemDetails.class, Set.of()));

        // A write that removes a field (`location: null`) and leaves another alone (`description` is absent): the
        // generated model keeps the explicit null and keeps the absent member absent, which is what makes a client able
        // to say either. The comparison is exact, in both directions: a model that drops the null, or writes the absent
        // member as null, differs.
        ok &= report(
                "the generated Java model keeps an explicit null and an absent member apart",
                through(mapper, write, EventView.class, Set.of()));
        JsonNode written = mapper.readTree(mapper.writeValueAsString(mapper.readValue(write, EventView.class)));
        if (!written.has("location") || !written.get("location").isNull() || written.has("description")) {
            System.err.println("FAILED: the generated model must write location as null and leave description out: " + written);
            ok = false;
        }

        // Values of a later version of the API.
        ObjectNode later = (ObjectNode) mapper.readTree(event);
        later.put("status", "postponed");
        ((ObjectNode) ((ArrayNode) later.get("attendees")).get(0)).put("partstat", "vanished");
        ok &= report(
                "the event with enumeration values of a later API version is read, not rejected",
                through(mapper, mapper.writeValueAsString(later), EventView.class, Set.of("/status", "/attendees/0/partstat")));

        ObjectNode newer = (ObjectNode) mapper.readTree(problem);
        newer.put("code", "a-code-of-a-later-version");
        ok &= report(
                "the problem with a code of a later API version is read, not rejected",
                through(mapper, mapper.writeValueAsString(newer), ProblemDetails.class, Set.of("/code")));

        if (!ok) {
            System.exit(1);
        }
    }
}
