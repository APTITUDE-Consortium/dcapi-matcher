use crate::{CredmanApply, CredmanFieldContext, CredmanFieldSetContext};
use core::ffi::CStr;
use std::borrow::Cow;

/// A key-value detail field displayed in an entry's detail section.
///
/// Constraints:
/// - `display_name` must not be empty
/// - `display_value` must not be empty when provided
#[derive(Debug, Clone)]
pub struct Field<'a> {
    pub display_name: Cow<'a, CStr>,
    pub display_value: Option<Cow<'a, CStr>>,
}

impl<'a> Field<'a> {
    pub fn new(display_name: &'a CStr, display_value: Option<&'a CStr>) -> Self {
        Self {
            display_name: Cow::Borrowed(display_name),
            display_value: display_value.map(Cow::Borrowed),
        }
    }

    pub fn from_cow(display_name: Cow<'a, CStr>, display_value: Option<Cow<'a, CStr>>) -> Self {
        Self {
            display_name,
            display_value,
        }
    }
}

impl<'a, 'b> CredmanApply<CredmanFieldContext<'b>> for Field<'a> {
    fn apply(&self, ctx: CredmanFieldContext<'b>) {
        ctx.host.add_field_for_string_id_entry(ctx.cred_id, self);
    }
}

impl<'a, 'b> CredmanApply<CredmanFieldSetContext<'b>> for Field<'a> {
    fn apply(&self, ctx: CredmanFieldSetContext<'b>) {
        ctx.v2
            .add_field_to_entry_set(self, ctx.cred_id, ctx.set_id, ctx.set_index);
    }
}
