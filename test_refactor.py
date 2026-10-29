import re

with open("src/lib.rs", "r") as f:
    content = f.read()

new_func = """fn request_delivery_route(action: &Action, target: &TargetRef) -> DeliveryRoute {
    match target {
        TargetRef::Element { .. } => match action {
            Action::Invoke
            | Action::SetValue { .. }
            | Action::SelectText { .. }
            | Action::PerformSecondaryAction { .. } => DeliveryRoute::TargetAddressed,
            Action::Scroll { .. } => {
                if cfg!(target_os = "macos") {
                    native_pointer_delivery_route()
                } else {
                    DeliveryRoute::TargetAddressed
                }
            }
            _ => native_pointer_delivery_route(),
        },
        _ => DeliveryRoute::Pointer,
    }
}"""

old_func = """fn request_delivery_route(action: &Action, target: &TargetRef) -> DeliveryRoute {
    match (action, target) {
        (
            Action::Invoke
            | Action::SetValue { .. }
            | Action::SelectText { .. }
            | Action::PerformSecondaryAction { .. },
            TargetRef::Element { .. },
        ) => DeliveryRoute::TargetAddressed,
        (Action::Scroll { .. }, TargetRef::Element { .. }) => {
            if cfg!(target_os = "macos") {
                native_pointer_delivery_route()
            } else {
                DeliveryRoute::TargetAddressed
            }
        }
        (_, TargetRef::Element { .. }) => native_pointer_delivery_route(),
        _ => DeliveryRoute::Pointer,
    }
}"""

if old_func in content:
    content = content.replace(old_func, new_func)
    with open("src/lib.rs", "w") as f:
        f.write(content)
    print("Replaced!")
else:
    print("Not found!")
