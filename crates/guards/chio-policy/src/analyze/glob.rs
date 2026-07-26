use std::collections::{HashMap, VecDeque};

use crate::glob_pattern::{tokenize, GlobToken};

use super::{AnalysisBudget, AnalysisError};

#[derive(Clone, Debug)]
pub(crate) struct GlobAutomaton {
    tokens: Vec<GlobToken>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlobRelation {
    Disjoint,
    Equal,
    SubsetOf,
    SupersetOf,
    Overlapping,
}

pub(crate) fn pattern_matches_empty(pattern: &str) -> bool {
    tokenize(pattern)
        .iter()
        .all(|token| matches!(token, GlobToken::StarNonSlash | GlobToken::StarNonNewline))
}

impl GlobAutomaton {
    pub(crate) fn compile(pattern: &str, max_chars: usize) -> Result<Self, AnalysisError> {
        let char_count = pattern.chars().count();
        if char_count > max_chars {
            return Err(AnalysisError::PatternLimit {
                length: char_count,
                maximum: max_chars,
            });
        }

        Ok(Self {
            tokens: tokenize(pattern),
        })
    }

    fn start(&self) -> Vec<usize> {
        self.epsilon_closure(vec![0])
    }

    fn accepts(&self, state: &[usize]) -> bool {
        state.binary_search(&self.tokens.len()).is_ok()
    }

    fn transition(&self, state: &[usize], ch: char) -> Vec<usize> {
        let mut next = Vec::new();
        for &position in state {
            let Some(token) = self.tokens.get(position) else {
                continue;
            };
            let destination = match token {
                GlobToken::Literal(expected) if *expected == ch => Some(position + 1),
                GlobToken::AnyNonNewline if ch != '\n' => Some(position + 1),
                GlobToken::StarNonSlash if ch != '/' => Some(position),
                GlobToken::StarNonNewline if ch != '\n' => Some(position),
                _ => None,
            };
            if let Some(destination) = destination {
                next.push(destination);
            }
        }
        self.epsilon_closure(next)
    }

    fn epsilon_closure(&self, mut state: Vec<usize>) -> Vec<usize> {
        state.sort_unstable();
        state.dedup();
        let mut cursor = 0;
        while cursor < state.len() {
            let position = state[cursor];
            if matches!(
                self.tokens.get(position),
                Some(GlobToken::StarNonSlash | GlobToken::StarNonNewline)
            ) {
                let next = position + 1;
                if let Err(index) = state.binary_search(&next) {
                    state.insert(index, next);
                }
            }
            cursor += 1;
        }
        state
    }

    fn literal_value(&self) -> Option<String> {
        self.tokens
            .iter()
            .map(|token| match token {
                GlobToken::Literal(ch) => Some(*ch),
                _ => None,
            })
            .collect()
    }
}

fn alphabet(
    automata: &[GlobAutomaton],
    budget: &mut AnalysisBudget,
) -> Result<Vec<char>, AnalysisError> {
    let mut chars = vec!['/', '\n'];
    for automaton in automata {
        for token in &automaton.tokens {
            let GlobToken::Literal(ch) = token else {
                continue;
            };
            budget.consume_alphabet_work()?;
            chars.push(*ch);
        }
    }
    chars.sort_unstable();
    chars.dedup();

    for candidate in (' '..='~')
        .chain(['\0', '\t', '\r', 'é', '中'])
        .chain((0..=char::MAX as u32).filter_map(char::from_u32))
    {
        budget.consume_alphabet_work()?;
        if chars.binary_search(&candidate).is_err() {
            chars.push(candidate);
            break;
        }
    }
    Ok(chars)
}

fn reconstruct<State>(nodes: &[(State, Option<(usize, char)>)], mut index: usize) -> String {
    let mut reversed = Vec::new();
    while let Some((parent, ch)) = nodes[index].1 {
        reversed.push(ch);
        index = parent;
    }
    reversed.reverse();
    reversed.into_iter().collect()
}

fn component_state_cost(state: &[usize]) -> usize {
    state.len().max(1)
}

fn pair_state_cost(state: &(Vec<usize>, Vec<usize>)) -> usize {
    component_state_cost(&state.0).saturating_add(component_state_cost(&state.1))
}

fn combined_state_cost(state: &[Vec<usize>]) -> usize {
    state
        .iter()
        .map(|component| component_state_cost(component))
        .fold(0usize, usize::saturating_add)
        .max(1)
}

fn pair_witness(
    left: &GlobAutomaton,
    right: &GlobAutomaton,
    budget: &mut AnalysisBudget,
    goal: impl Fn(bool, bool) -> bool,
) -> Result<Option<String>, AnalysisError> {
    type PairState = (Vec<usize>, Vec<usize>);

    if let (Some(left), Some(right)) = (left.literal_value(), right.literal_value()) {
        if left == right {
            return Ok(goal(true, true).then_some(left));
        }
        if goal(true, false) {
            return Ok(Some(left));
        }
        return Ok(goal(false, true).then_some(right));
    }

    let alphabet = alphabet(&[left.clone(), right.clone()], budget)?;
    let start = (left.start(), right.start());
    budget.consume_automaton_states(pair_state_cost(&start))?;
    let mut nodes: Vec<(PairState, Option<(usize, char)>)> = vec![(start.clone(), None)];
    let mut visited = HashMap::from([(start, 0usize)]);
    let mut queue = VecDeque::from([0usize]);

    while let Some(index) = queue.pop_front() {
        let (left_state, right_state) = nodes[index].0.clone();
        if goal(left.accepts(&left_state), right.accepts(&right_state)) {
            return Ok(Some(reconstruct(&nodes, index)));
        }
        for &ch in &alphabet {
            budget.consume_automaton_transition()?;
            let next = (
                left.transition(&left_state, ch),
                right.transition(&right_state, ch),
            );
            if visited.contains_key(&next) {
                continue;
            }
            budget.consume_automaton_states(pair_state_cost(&next))?;
            let next_index = nodes.len();
            visited.insert(next.clone(), next_index);
            nodes.push((next, Some((index, ch))));
            queue.push_back(next_index);
        }
    }
    Ok(None)
}

pub(crate) fn relation(
    left: &GlobAutomaton,
    right: &GlobAutomaton,
    budget: &mut AnalysisBudget,
) -> Result<GlobRelation, AnalysisError> {
    let left_only = pair_witness(left, right, budget, |a, b| a && !b)?.is_some();
    let right_only = pair_witness(left, right, budget, |a, b| !a && b)?.is_some();
    match (left_only, right_only) {
        (false, false) => Ok(GlobRelation::Equal),
        (false, true) => Ok(GlobRelation::SubsetOf),
        (true, false) => Ok(GlobRelation::SupersetOf),
        (true, true) => {
            let intersects = pair_witness(left, right, budget, |a, b| a && b)?.is_some();
            if intersects {
                Ok(GlobRelation::Overlapping)
            } else {
                Ok(GlobRelation::Disjoint)
            }
        }
    }
}

pub(crate) fn find_combined_witness(
    automata: &[GlobAutomaton],
    budget: &mut AnalysisBudget,
    mut goal: impl FnMut(&[bool], &str, &mut AnalysisBudget) -> Result<bool, AnalysisError>,
) -> Result<Option<String>, AnalysisError> {
    type CombinedState = Vec<Vec<usize>>;

    let alphabet = alphabet(automata, budget)?;
    let start: CombinedState = automata.iter().map(GlobAutomaton::start).collect();
    budget.consume_automaton_states(combined_state_cost(&start))?;
    let mut nodes: Vec<(CombinedState, Option<(usize, char)>)> = vec![(start.clone(), None)];
    let mut visited = HashMap::from([(start, 0usize)]);
    let mut queue = VecDeque::from([0usize]);

    while let Some(index) = queue.pop_front() {
        let matches: Vec<bool> = automata
            .iter()
            .zip(&nodes[index].0)
            .map(|(automaton, state)| automaton.accepts(state))
            .collect();
        let witness = reconstruct(&nodes, index);
        if goal(&matches, &witness, budget)? {
            return Ok(Some(witness));
        }
        for &ch in &alphabet {
            budget.consume_automaton_transition()?;
            let next: CombinedState = automata
                .iter()
                .zip(&nodes[index].0)
                .map(|(automaton, state)| automaton.transition(state, ch))
                .collect();
            if visited.contains_key(&next) {
                continue;
            }
            budget.consume_automaton_states(combined_state_cost(&next))?;
            let next_index = nodes.len();
            visited.insert(next.clone(), next_index);
            nodes.push((next, Some((index, ch))));
            queue.push_back(next_index);
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{alphabet, pattern_matches_empty, GlobAutomaton};
    use crate::analyze::{AnalysisBudget, AnalysisError, AnalysisOptions};

    #[test]
    fn only_star_tokens_match_the_empty_string() {
        assert!(pattern_matches_empty(""));
        assert!(pattern_matches_empty("***"));
        assert!(!pattern_matches_empty("?"));
        assert!(!pattern_matches_empty("repo.*"));
    }

    #[test]
    fn adversarial_unicode_alphabet_exhausts_aggregate_work() {
        let pattern: String = (0..4_096).filter_map(char::from_u32).collect();
        let automata = (0..25)
            .map(|_| GlobAutomaton::compile(&pattern, 4_096).expect("compile unicode glob"))
            .collect::<Vec<_>>();
        let mut budget = AnalysisBudget::new(AnalysisOptions::default());
        let error = alphabet(&automata, &mut budget).expect_err("alphabet work limit");
        assert!(matches!(error, AnalysisError::AlphabetWorkLimit { .. }));
    }
}
