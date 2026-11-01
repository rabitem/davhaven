//! Representative samples of the suites that run one world per case.
//!
//! A case that needs a world of its own costs seconds on PostgreSQL, so the runs of pull requests perform a sample of such
//! a suite and the nightly run all of it (`CONFORMANCE_FULL=1`, see [`crate::permissions::RunOptions::for_store`]).
//! The sample of a suite is the fewest cases that between them have every value of every dimension of the suite at least
//! once; [`cover`] chooses them.

use std::collections::BTreeSet;

/// The items, few, that between them have every facet that any item has at least once, in the order they were given.
///
/// The choice is greedy: the item that adds the most facets that nothing chosen has comes next, and of equal ones the
/// first. A facet is a string that names a value of a dimension (`client davx5`), so that two dimensions never share one.
pub(crate) fn cover<T>(items: &[T], facets: impl Fn(&T) -> Vec<String>) -> Vec<&T> {
    let facets_of: Vec<Vec<String>> = items.iter().map(facets).collect();
    let mut wanted: BTreeSet<&str> = facets_of.iter().flatten().map(String::as_str).collect();
    let mut taken = vec![false; items.len()];
    while !wanted.is_empty() {
        let best = facets_of
            .iter()
            .enumerate()
            .filter(|(position, _)| taken.get(*position) == Some(&false))
            .map(|(position, own)| {
                let new = own.iter().filter(|facet| wanted.contains(facet.as_str())).count();
                (new, position)
            })
            .filter(|(new, _)| *new > 0)
            .min_by_key(|(new, position)| (core::cmp::Reverse(*new), *position));
        let Some((_, position)) = best else {
            break;
        };
        for facet in facets_of.get(position).into_iter().flatten() {
            wanted.remove(facet.as_str());
        }
        if let Some(flag) = taken.get_mut(position) {
            *flag = true;
        }
    }
    items
        .iter()
        .zip(taken)
        .filter(|(_, chosen)| *chosen)
        .map(|(item, _)| item)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An item is the list of its facets.
    fn chosen(items: &[&[&str]]) -> Vec<usize> {
        let items: Vec<(usize, Vec<String>)> = items
            .iter()
            .enumerate()
            .map(|(position, facets)| (position, facets.iter().map(|facet| (*facet).to_owned()).collect()))
            .collect();
        cover(&items, |(_, facets)| facets.clone())
            .iter()
            .map(|(position, _)| *position)
            .collect()
    }

    #[test]
    fn the_item_that_adds_the_most_comes_first_and_the_first_of_equals_wins() {
        // Everything adds two to begin with and the first is taken; then the third adds two and the fifth does, the rest one.
        let items: [&[&str]; 5] = [&["a", "x"], &["a", "y"], &["b", "y"], &["b", "x"], &["c", "z"]];
        assert_eq!(chosen(&items), vec![0, 2, 4]);
    }

    #[test]
    fn every_facet_is_had_and_nothing_is_chosen_for_nothing() {
        assert_eq!(chosen(&[]), Vec::<usize>::new());
        assert_eq!(
            chosen(&[&[], &[]]),
            Vec::<usize>::new(),
            "items without facets add nothing"
        );
        // The second item alone has everything the others have.
        assert_eq!(chosen(&[&["a"], &["a", "b", "c"], &["c"]]), vec![1]);
    }
}
